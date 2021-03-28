unit Constant_Fold;

interface
  uses System.SysUtils, System.StrUtils,Winapi.Windows,Vcl.Dialogs,
       ACTypes,Capstone,CapstoneX86,Convert, Assemble,
       System.Generics.Collections;

const
  STACK_TOP      : array[0..1] of string = ('esp:unknown:1:0', 'rsp:unknown:1:0');
  STACK_TOP_DISP : array[0..1] of string = ('esp:unknown:1:4', 'rsp:unknown:1:8');

  MATHOP_1 : array[0..3] of x86_insn = (X86_INS_NOT,X86_INS_NEG,X86_INS_INC,X86_INS_DEC) ;
  MATHOP_2 : array[0..6] of x86_insn = (X86_INS_ADD,X86_INS_SUB,X86_INS_XOR,X86_INS_AND,X86_INS_OR,X86_INS_SHR,X86_INS_SHL) ;
  JCC_OP   : array[0..21] of x86_insn =( X86_INS_CALL,X86_INS_JMP, X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ,
                                         X86_INS_JE,  X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JMP,  X86_INS_JNE,
                                         X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ,X86_INS_JS ) ;
  BLACKLIST_OP : array[0..1] of x86_insn =( X86_INS_CMPXCHG, X86_INS_XCHG );

type
  TConstFold = class
   private
    FModo      : Byte;  //32 or 64

    function IsContiene(const AArray: TArray<String> ;const AString: String ): boolean; overload;
    function IsContiene(const AArray: array of x86_insn ;const ANumber: Mnemonics ): boolean; overload;
    function Const_Propagate(instruction: TIstruzione; items: TDictionary<String,Int64>; var lReplace: Boolean): TIstruzione;
    function Solve(op: Mnemonics; imm1, imm2: Int64; size: Byte):Uint64;
    procedure Clean(const insn: TIstruzione; var items: TDictionary<String, Int64>);
    function constantFoldingMem(const block: TArray<TIstruzione>;var Res: TArray<TIstruzione>): Boolean;
    function memLabel(op: ACTypes.TOperand): string;
    function ComponiMem(mem: TMemoria; size: byte): string;
    function constantFoldingReg(const block : TArray<TIstruzione>; var Res : TArray<TIstruzione>; lPush : Boolean = False):Boolean;
   public

    constructor Create(Archi: Byte = CP_MODE_32);
    function    constantFolding(var block : TArray<TIstruzione>; lPush : Boolean = False): Boolean;

    property Modo       : Byte read FModo write FModo;
  end;

implementation

function TConstFold.IsContiene(const AArray: TArray<String> ;const AString: String ): boolean;
var
  i: integer;
begin
    for i := Low(AArray) to High(AArray) do
      if AString =  AArray[i]  then
        Exit(true);
    result := false;
end;

constructor TConstFold.Create(Archi: Byte = CP_MODE_32);
begin
    FModo := Archi;
end;

function TConstFold.IsContiene(const AArray: array of x86_insn ;const ANumber: Mnemonics ): boolean;
var
  i: integer;
begin
    for i := Low(AArray) to High(AArray) do
      if ANumber = Mnemonics( AArray[i] ) then
        Exit(true);
    result := false;
end;

//  var lReplace: Boolean --fp00000025-- update anche solo se cambio di un valore
function TConstFold.Const_Propagate(instruction: TIstruzione; items: TDictionary<String,Int64>; var lReplace: Boolean): TIstruzione;
var
 ignored : TArray<String>;
 ops     : array[0..3] of TOperand;
 op      : TOperand;
 i       : Integer;
 insn_str: string;
 item    : TPair<String,Int64>;
 newIstr : TIstruzione;

begin
    for i := 0 to High(instruction.operands) do
       ops[i] := instruction.operands[i];

    // Check if the instruction is blacklisted
    if IsContiene(JCC_OP,instruction.opcode.mnem) then
          Exit(instruction) ;

    // Check if the instruction is blacklisted
    if IsContiene(BLACKLIST_OP,instruction.opcode.mnem) then
             ignored := ignored + [ gConvert.reg2str(ops[1].reg.reg) ];

    // Ignore the first operand unless whitelisted
    if instruction.opcode.mnem <> Ord(X86_INS_PUSH) then
            if instruction.opCount > 0 then
                    if ops[0].Tipo = T_REG then
                            ignored := ignored + [ gConvert.reg2str(ops[0].reg.reg) ];

    // Ignore the base register of the memory
    for op in ops do
    begin
        if op.Tipo = T_MEM then
        begin
             ignored := ignored + [ gConvert.reg2str(op.mem.base.reg) ];
             ignored := ignored + [ gConvert.reg2str(op.mem.index.reg) ];
        end;
    end;

    // Substitute the values into the instruction string
    insn_str := instruction.ToString;
    lReplace := False;
    for item in items do
    begin
        if not ( IsContiene(ignored, item.Key)) and (instruction.opcode.mnem <> Ord(X86_INS_POP)) and (instruction.opcode.mnem <> Ord(X86_INS_PUSH))then
        begin
             // --fp00000008--
             if SearchBuf(PChar(insn_str), Length(insn_str),0, 0, item.Key,[soDown,soWholeWord]) <> nil then
             begin
                 lReplace := True;
                 insn_str := StringReplace(insn_str,item.Key, string('0x'+ fIntToHex(item.Value)) ,[rfReplaceAll] ) ;
             end;
        end;
    end;

    newIstr := ACAssemble(AnsiString(insn_str), instruction, FModo );

    Result := newIstr;
end;

function TConstFold.Solve(op: Mnemonics; imm1, imm2: Int64; size: Byte):Uint64;
var
  mask : UInt64;

begin
    Result := 0;

    mask := $FFFFFFFFFFFFFFFF;
    if      size = 4 then mask := $FFFFFFFF
    else if size = 2 then mask := $FFFF
    else if size = 1  then mask := $FF ;

    if      op = ord(X86_INS_ADD) then   Exit ((imm1 + imm2) and mask)
    else if op = ord(X86_INS_SUB) then   Exit ((imm1 - imm2) and mask)
    else if op = ord(X86_INS_XOR) then   Exit ((imm1 xor imm2) and mask)
    else if op = ord(X86_INS_AND) then   Exit ((imm1 and imm2) and mask)
    else if op = ord(X86_INS_OR)  then   Exit ((imm1 or imm2) and mask)
    else if op = ord(X86_INS_SHR) then   Exit ((imm1 shr imm2) and mask)
    else if op = ord(X86_INS_SHL) then   Exit ((imm1 shl imm2) and mask)
    else if op = ord(X86_INS_INC) then   Exit ((imm1 + 1) and mask)
    else if op = ord(X86_INS_DEC) then   Exit ((imm1 - 1) and mask)
    else if op = ord(X86_INS_NOT) then   Exit ((not imm1) and mask)
    else if op = ord(X86_INS_NEG) then   Exit ((-imm1) and mask)
    else
            ShowMessage('solve() unsupported operation: ' + gConvert.ins2str(op)) ;

end;

procedure TConstFold.Clean(const insn  : TIstruzione; var items : TDictionary<String,Int64>);
var
  regWrite,
  RegItem : TRegister;
  sReg    : String ;
  strRegs : TArray<string>;
begin

   strRegs := items.Keys.ToArray;
   // fp00000004
   for regWrite in insn.regs_written do
   begin
        for sReg in strRegs do
        begin
            RegItem.reg := gConvert.str2reg(sReg);

            if sReg = gConvert.reg2str(regWrite.reg) then
            begin
                items.Remove(sReg);
            end             // sub ax, ecx
            else if RegItem.GetParent = regWrite.GetParent then
            begin
                items.Remove( gConvert.reg2str(  TRegisters(RegItem.GetParent)) );
                                                                    // testing!!!!!!!!!!!!!!! mov esi, 0.......mov si, word[edx] -- fp00000029 --
                if (regWrite.Size >= RegItem.Size) or ((regWrite.Size = 4) and (RegItem.Size = 8))  or ( (regWrite.Size < RegItem.Size) and (insn.operands[1].Tipo = T_MEM) )then
                begin
                    items.Remove(sReg);
                    // Se elimino il subreg elimino pure il parent !!!  // Modified by Max 17/08/2020 13:43:18
                    if items.ContainsKey( gConvert.reg2str(  TRegisters(RegItem.GetParent)) ) then
                       items.Remove( gConvert.reg2str(  TRegisters(RegItem.GetParent)) );
                end;
            end;

        end;
   end;
end;

function TConstFold.constantFolding(var block : TArray<TIstruzione>; lPush : Boolean = False): Boolean;
var
  simplified : Boolean;
begin
    Result := False;

    simplified := constantFoldingReg(block, block,lPush);
    if simplified then Result := True;

    simplified := constantFoldingMem(block, block);
    if simplified then Result := True;
end;

function TConstFold.constantFoldingReg(const block : TArray<TIstruzione>; var Res : TArray<TIstruzione>; lPush : Boolean = False):Boolean;
var
  instruction,
  instruction1,
  newIstr     : TIstruzione;
  op1,op2     : TOperand;
  reg         : String;
  Val1,Val2,
  ResVal      : Int64;
  items       : TDictionary<String,Int64>;
  tmpRes      : TArray<TIstruzione>;
  idx,j       : Integer;
  lOk         : Boolean;
  lReplace    : Boolean;
  rReg        : TRegisters;
begin
    Result   := False;
    lReplace := False;
    rReg     := REG_INVALID;

    try
      SetLength(tmpRes,0);
      if Length(block) = 0 then //empty input cannot be optimized
         Exit(False);

      items  := TDictionary<String,Int64>.Create;

      for idx := 0 to High(block) do
      begin
          lOk := False;

          // get instruction
          instruction := block[idx];

          if lpush then
          begin
              if ( (instruction.opcode.mnem = Mnemonics(X86_INS_MOV)) or (instruction.opcode.mnem = Mnemonics(X86_INS_MOVABS)) )then
              begin
                  {$IFDEF  TESTING}
                  var ss : AnsiString := instruction.ToString(True);
                  OutputDebugStringA(PAnsiChar(ss));
                  {$ENDIF}
                  if ((idx - 1) >= 0) and (block[idx-1].opcode.mnem = Mnemonics(X86_INS_PUSH)) then
                  begin
                      rReg := block[idx-1].operands[0].reg.reg;
                      lOk  := True;
                  end;
              end;

              if lok then
              begin
                  for j := (idx+1) to High(block) do
                  begin
                      if (block[j].opcode.mnem = Mnemonics(X86_INS_PUSH)) then
                      begin
                          lOk := False;
                          Break;
                      end
                      else if (block[j].opcode.mnem = Mnemonics(X86_INS_POP)) then
                      begin
                          if block[j].operands[0].reg.reg <>  rReg then
                          begin
                              lOk := False;
                              Break;
                          end
                          else Break;
                      end
                  end;
              end;

          end else
          begin
               if (instruction.opcode.mnem = Mnemonics(X86_INS_MOV)) or (instruction.opcode.mnem = Mnemonics(X86_INS_MOVABS)) then
                 lOk := True;
          end;

          // add movabs--fp00000006--
          if  lOk then
          begin
              op1 := instruction.operands[0];
              op2 := instruction.operands[1];

              if (op1.Tipo = T_REG) and (op2.Tipo = T_IMM)then
              begin
                  items.AddOrSetValue(gConvert.reg2str(op1.reg.reg),op2.imm.Value);
                  // verificare!!!! per adesso ok  --fp00000005--
                  items.AddOrSetValue(gConvert.reg2str(TRegisters(op1.reg.GetParent)),op2.imm.Value);

                  tmpRes := tmpRes + [ instruction ];
              end else
              begin
                  instruction1 := Const_Propagate(instruction, items,lReplace);
                  if (Result = False) and (lReplace = True) then  Result := True;
                  tmpRes := tmpRes + [ instruction1 ];
                  clean(instruction, items)
              end;
          end
          else if IsContiene(MATHOP_1, instruction.opcode.mnem)   then
          begin
              op1 := instruction.operands[0];

              if op1.Tipo =  T_REG then
              begin
                  reg := gConvert.reg2str(op1.reg.reg);
                  if not items.ContainsKey(reg) then
                  begin
                      // se contiene il registro operazioni su sottoregistri
                      if items.ContainsKey( gConvert.reg2str(TRegisters(op1.reg.GetParent)) ) then
                      begin
                          items.AddOrSetValue( gConvert.reg2str( TRegisters(op1.reg.GetReg(op1.reg.GetParent,op1.reg.Size) ) ),items[gConvert.reg2str(TRegisters(op1.reg.GetParent))]);
                      end;
                  end;

                  if items.ContainsKey(reg) then
                  begin
                      Val1  := items[reg];
                      ResVal := solve(instruction.opcode.mnem, Val1, 0, op1.Size.Value);
                      items.AddOrSetValue(reg,ResVal);
                      // verificare!!!! per adesso ok  (modifica sopratutto per x64   --fp00000005--
                      items.AddOrSetValue(gConvert.reg2str(TRegisters(op1.reg.GetParent)),ResVal);
                      // update valore nel caso operazioni a x64 aggiornare sottoreg
                      if op1.Size.Value = 8 then
                        items.AddOrSetValue( gConvert.reg2str( TRegisters(op1.reg.GetReg(op1.reg.GetParent,4) ) ), ResVal);

                      newIstr := ACAssemble('mov ' + AnsiString(op1.ToString) + ', ' + '0x'+ fIntToHex(ResVal), instruction, FModo);
                      tmpRes := tmpRes + [ newIstr ];
                      Result := True;
                  end else
                  begin
                      instruction1 := Const_Propagate(instruction, items,lReplace);
                      if (Result = False) and (lReplace = True) then Result := True;
                      tmpRes := tmpRes + [ instruction1 ];
                  end;
              end else
              begin
                  instruction1 := Const_Propagate(instruction, items,lReplace);
                  if (Result = False) and (lReplace = True) then  Result := True;
                  tmpRes := tmpRes + [ instruction1 ];
                  clean(instruction, items) ;
              end
          end
          else if IsContiene(MATHOP_2, instruction.opcode.mnem) then
          begin
              op1 := instruction.operands[0];
              op2 := instruction.operands[1];

              if (op1.Tipo =  T_REG) and (op2.Tipo =  T_IMM) then
              begin
                  reg := gConvert.reg2str(op1.reg.reg);
                  if not items.ContainsKey(reg) then
                  begin
                      // se contiene il registro operazioni su sottoregistri
                      if items.ContainsKey( gConvert.reg2str(TRegisters(op1.reg.GetParent)) ) then
                      begin
                          items.AddOrSetValue( gConvert.reg2str( TRegisters(op1.reg.GetReg(op1.reg.GetParent,op1.reg.Size) ) ),items[gConvert.reg2str(TRegisters(op1.reg.GetParent))]);
                      end;
                  end;

                  if items.ContainsKey(reg) then
                  begin
                      Val1  := items[reg];
                      Val2  := op2.imm.Value;
                      ResVal := solve(instruction.opcode.mnem, Val1, Val2, op1.Size.Value);
                      items.AddOrSetValue(reg,ResVal);
                      // verificare!!!! per adesso ok  (modifica sopratutto per x64  --fp00000005--
                      items.AddOrSetValue(gConvert.reg2str(TRegisters(op1.reg.GetParent)),ResVal);
                      // update valore nel caso operazioni a x64 aggiornare sottoreg
                      if op1.Size.Value = 8 then
                        items.AddOrSetValue( gConvert.reg2str( TRegisters(op1.reg.GetReg(op1.reg.GetParent,4) ) ), ResVal);

                      newIstr := ACAssemble('mov ' + AnsiString(op1.ToString) + ', ' + '0x'+ fIntToHex(ResVal), instruction,FModo);
                      tmpRes := tmpRes + [ newIstr ];
                      Result := True;
                  end else
                  begin
                      instruction1 := Const_Propagate(instruction, items,lReplace);
                      if (Result = False) and (lReplace = True) then  Result := True;
                      tmpRes := tmpRes + [ instruction1 ];
                  end;
              end else
              begin
                  instruction1 := Const_Propagate(instruction, items,lReplace);
                  if (Result = False) and (lReplace = True) then  Result := True;
                  tmpRes := tmpRes + [ instruction1 ];
                  clean(instruction, items);
                  // Se il primo operando è un registro gia registrato si deve eliminare perchè il valore è
                  // modificato dall'attuale istruzione

              end
          end else
          begin
              instruction1 := Const_Propagate(instruction, items,lReplace);
              if (Result = False) and (lReplace = True) then  Result := True;
              tmpRes := tmpRes + [ instruction1 ];
              // jcc blocca esecuzione -- deobfuscare singoli basic bloc come principio
              if IsContiene(JCC_OP, instruction1.opcode.mnem)   then items.Clear
              else                                                   clean(instruction, items);
          end;
      end;
    finally
      Res := tmpRes;
    end;

end;

function TConstFold.memLabel(op : ACTypes.TOperand): string;
var
  base, index : string;
  scale,disp,Size : Int64;
begin
    base  := gConvert.reg2str(op.mem.base.reg);
    index := gConvert.reg2str(op.mem.index.reg);
    scale := op.mem.scale.Value;
    disp  := op.mem.disp.Value;
    size  := op.Size.Value;

    if index = '' then  index := 'unknown';


    Result :=  base + ':' + index + ':' + IntToStr(scale) + ':' + IntToStr(disp) + ':' + IntToStr(size)
end;

function TConstFold.ComponiMem(mem: TMemoria; size: byte): string;
var
  size_indicator : string;
  base, index    : string;
  disp,scale     : string;
begin
        // Generate size indicator
        size_indicator := '';
        base  := gConvert.reg2str(mem.base.reg);
        index := gConvert.reg2str(mem.index.reg);
        disp  := mem.disp.ToString;
        scale := mem.scale.ToString;

        if      size = 8 then   size_indicator := 'qword ptr'
        else if size = 4 then   size_indicator := 'dword ptr'
        else if size = 2 then   size_indicator := 'word ptr'
        else if size = 1 then   size_indicator := 'byte ptr'
        else                    size_indicator := '';

        if  (mem.base.reg <> REG_INVALID) and (mem.index.reg <> REG_INVALID) then
                Result := size_indicator + ' [' + base + ' + ' + index + ' * ' + scale + ' + ' + disp + ']'
        else if (mem.base.reg <> REG_INVALID) and (mem.index.reg = REG_INVALID) then
                Result := size_indicator + ' [' + base + ' + ' + disp + ']'
        else if (mem.base.reg = REG_INVALID) and (mem.index.reg <> REG_INVALID) then
                Result := size_indicator + ' [' + index + ' * ' + scale + ' + ' + disp + ']'
        else
                Result := size_indicator + ' [' + disp + ']'
end;

function TConstFold.constantFoldingMem(const block : TArray<TIstruzione>; var Res : TArray<TIstruzione>):Boolean;
var
  tmpRes      : TArray<TIstruzione>;
  start_found : Boolean;
  start_val   : int64;
  ResVal,Val2 : Int64;
  instruction,
  newIstr     : TIstruzione;
  op1,op2     : ACTypes.TOperand;
  strStack    : string;
  strStackDisp: string;
  StrMem      : string;

begin
    Result      := False;
    start_val   := 0;
    start_found := False;
    StrMem      := '';

    try
      SetLength(tmpRes,0);
      if Length(block) = 0 then //empty input cannot be optimized
           Exit(False);

      for instruction in  block do
      begin
          if      FModo = CP_MODE_32 then strStack := STACK_TOP[0]
          else if FModo = CP_MODE_64 then strStack := STACK_TOP[1];

          if      FModo = CP_MODE_32 then strStackDisp := STACK_TOP_DISP[0]
          else if FModo = CP_MODE_64 then strStackDisp := STACK_TOP_DISP[1];

          if instruction.opcode.mnem = Mnemonics(X86_INS_PUSH) then
          begin
              op1 := instruction.operands[0] ;

              if (op1.Tipo = T_IMM) then
              begin
                  start_val   := op1.imm.Value;
                  start_found := True;
                  tmpRes      := tmpRes + [ instruction ]
              end else
              begin
                  tmpRes      := tmpRes + [ instruction ];
                  start_found := False;
              end;
          end
          else if instruction.opcode.mnem = Mnemonics(X86_INS_MOV) then
          begin
              op1 := instruction.operands[0];
              op2 := instruction.operands[1];

              if (op1.Tipo = T_MEM) and (op2.Tipo = T_IMM) then
              begin
                  if Pos(strStack, memLabel(op1) ) > 0 then
                  begin
                      start_val   := op2.imm.Value;
                      start_found := True;
                      tmpRes      := tmpRes + [ instruction ];
                  end else
                  begin
                      // test // Modified by Max 11/08/2020 20:36:42
                      start_val   := op2.imm.Value;
                      start_found := True;
                      strMem      := memLabel(op1);
                      strStack    := '';
                      strStackDisp:= '';
                      tmpRes      := tmpRes + [ instruction ];
                  end;
              end else
              begin
                  tmpRes      := tmpRes + [ instruction ];
                  start_found := False ;
              end;
          end
          else if IsContiene(MATHOP_1, instruction.opcode.mnem) then
          begin
              op1 := instruction.operands[0];
              if op1.Tipo = T_MEM then
              begin
                  if (Pos(strStack, memLabel(op1) ) > 0) and (start_found) then
                  begin
                      ResVal    := solve(instruction.opcode.mnem, start_val, 0, op1.Size.Value) ;
                      start_val := ResVal;
                      newIstr   := ACAssemble('mov ' + AnsiString(ComponiMem(op1.mem, op1.Size.Value)) + ', ' + '0x'+ fIntToHex(ResVal), instruction, FModo);
                      //start_val := newIstr.operands[1].imm.Value;
                      tmpRes    := tmpRes + [ newIstr ];
                      Result    := True
                  end
                  // test // Modified by Max 11/08/2020 20:36:42
                  else if (strMem = memLabel(op1)) and (start_found) then
                  begin
                      ResVal    := solve(instruction.opcode.mnem, start_val, 0, op1.Size.Value) ;
                      start_val := ResVal;
                      newIstr   := ACAssemble('mov ' + AnsiString(ComponiMem(op1.mem, op1.Size.Value)) + ', ' + '0x'+ fIntToHex(ResVal), instruction, FModo);
                      // aggiorna istruzione
                      tmpRes    := tmpRes + [ newIstr ];
                      tmpRes[High(tmpRes)-1].address := $CCCCAAAA;
                      Result    := True
                  end else
                  //
                  begin
                      tmpRes      := tmpRes + [ instruction ];
                      start_found := False
                  end;
              end else
              begin
                  tmpRes      := tmpRes + [ instruction ];
                  start_found := False
              end;
          end
          else if IsContiene(MATHOP_2, instruction.opcode.mnem) then
          begin
              op1 := instruction.operands[0];
              op2 := instruction.operands[1];

              if (op1.Tipo = T_MEM) and (op2.Tipo = T_IMM) then
              begin
                  if (Pos(strStack, memLabel(op1) ) > 0) and (start_found) then
                  begin
                      val2      := op2.imm.Value;
                      ResVal    := solve(instruction.opcode.mnem, start_val, val2, op1.Size.Value);
                      start_val := ResVal;
                      newIstr   := ACAssemble('mov ' + AnsiString(ComponiMem(op1.mem, op1.Size.Value)) + ', ' + '0x'+ fIntToHex(ResVal), instruction, FModo);
                      //start_val := newIstr.operands[1].imm.Value;
                      tmpRes    := tmpRes + [ newIstr ];
                      Result    := True
                  end
                  // test // Modified by Max 11/08/2020 20:36:42
                  else if (strMem = memLabel(op1)) and (start_found) then
                  begin
                      val2      := op2.imm.Value;
                      ResVal    := solve(instruction.opcode.mnem, start_val, val2, op1.Size.Value);
                      start_val := ResVal;
                      newIstr   := ACAssemble('mov ' + AnsiString(ComponiMem(op1.mem, op1.Size.Value)) + ', ' + '0x'+ fIntToHex(ResVal), instruction, FModo);
                      DeleteRef(tmpRes, High(tmpRes),FModo);
                      // aggiorna istruzione
                      tmpRes    := tmpRes + [ newIstr ];
                      tmpRes[High(tmpRes)-1].address := $CCCCAAAA;
                      Result    := True
                  end else
                  //
                  begin
                      tmpRes      := tmpRes + [ instruction ];
                      start_found := False
                  end;
              end else
              begin
                  tmpRes      := tmpRes + [ instruction ];
                  start_found := False
              end;
          end else
          begin
              tmpRes      := tmpRes + [ instruction ];
              start_found := False
          end;
      end;
    finally
      Res := tmpRes;
    end;

end;

end.
