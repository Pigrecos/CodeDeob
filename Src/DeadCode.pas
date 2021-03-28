unit DeadCode;

interface
   uses System.SysUtils, Winapi.Windows,Vcl.Dialogs, System.Classes,
        ACTypes,Capstone,CapstoneX86,Convert, Assemble,
        System.Generics.Collections;

const
  whitelisted   : array[0..22] of x86_insn =( X86_INS_CMP,X86_INS_CALL,
                                              X86_INS_JMP, X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ,
                                              X86_INS_JE,  X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JMP,  X86_INS_JNE,
                                              X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ,X86_INS_JS ) ;

  ExList        : array[0..24] of x86_insn =( X86_INS_CMP,X86_INS_CALL, X86_INS_PUSH, X86_INS_POP,
                                              X86_INS_JMP, X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ,
                                              X86_INS_JE,  X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JMP,  X86_INS_JNE,
                                              X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ,X86_INS_JS ) ;

  JCC_OP   : array[0..21] of x86_insn =( X86_INS_CALL,X86_INS_JMP, X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ,
                                         X86_INS_JE,  X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JMP,  X86_INS_JNE,
                                         X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ,X86_INS_JS ) ;
type
  TExplicitInstruction = record
    read : TList<TRegister>;
    write: TList<TRegister>;
    ins  : TIstruzione;
    constructor Create(r,w: TList<TRegister>; vIns  : TIstruzione);
    function    Reads(reg: TRegister): Boolean;
    function    Writes(reg: TRegister): Boolean;
    function    IsOverwrites(reg: TRegister): Boolean;
  end;

  TDeadCode = class
    private
      FModo   : Byte;  //32 or 64

      function DeadCodeReg(const block : TArray<TIstruzione>; var Res : TArray<TIstruzione>):Boolean;

      function  readRegs(ins: TIstruzione): TList<TRegister>;
      function  WriteRegs(ins: TIstruzione): TList<TRegister>;
      function  IsOverwritten(ins: TIstruzione; exp_insn:TArray<TExplicitInstruction>;idxStart : Integer = 0): Boolean;
      function  isMemInsn(ins: TIstruzione): Boolean;
      function  IsContiene(const AArray: array of x86_insn; const ANumber: Mnemonics): boolean;
      function  DeadCodeNop(const block: TArray<TIstruzione>; var Res: TArray<TIstruzione>): Boolean;
      function  GetIndex(const AArray: TArray<TIstruzione>; const Address: UInt64; const StartIndex : Integer; var FoundIndex: Integer): boolean;
    public

    constructor Create(Archi: Byte = CP_MODE_32);
    function    DeadCode(var block: TArray<TIstruzione>): Boolean;
    function    DeadCodeMem(const block : TArray<TIstruzione>; var Res : TArray<TIstruzione>):Boolean;

    property Modo   : Byte    read FModo    write FModo;

  end;

implementation

procedure DebugMsg(const Msg: String);
begin
   {$IFDEF TESTING}OutputDebugString(PChar(Msg)) {$ENDIF}
end;

{ TExplicitInstruction }

constructor TExplicitInstruction.Create(r, w: TList<TRegister>; vIns: TIstruzione);
begin
    Self.read := r;
    Self.write:= w;
    Self.ins  := vIns;
end;

function TExplicitInstruction.IsOverwrites(reg: TRegister): Boolean;
var
 w : TRegister;
begin
    for w in self.write do
    begin
        if w.GetParent = reg.GetParent then
        begin
            if w.Size >= reg.Size              then   Exit(True);
            if (w.Size = 4) and (reg.Size = 8) then   Exit(True);
        end;
    end;
    Result := False
end;

function TExplicitInstruction.Reads(reg: TRegister): Boolean;
var
 r : TRegister;
begin
    for r in read do
      if r.GetParent = reg.GetParent then
        Exit(True);

    Result := False;
end;

function TExplicitInstruction.Writes(reg: TRegister): Boolean;
var
 w : TRegister;
begin
    for w in write do
      if w.GetParent = reg.GetParent then
        Exit(True);

    Result := False;
end;

{ TDeadCode }

constructor TDeadCode.Create(Archi: Byte = CP_MODE_32);
begin
    FModo    := Archi;
end;

// Extract READ registers
function TDeadCode.readRegs(ins : TIstruzione): TList<TRegister>;
var
  regs_read : TList<TRegister>;
  i         : Integer;

begin
    regs_read := TList<TRegister>.Create;
    for i := 0 to Length(ins.regs_read) - 1 do
       regs_read.Add(ins.regs_read[i]) ;

    Result := regs_read;
end;

// Extract WRITE registers
function TDeadCode.WriteRegs(ins : TIstruzione): TList<TRegister>;
var
  regs_write : TList<TRegister>;
  i    : Integer;
begin
    regs_write := TList<TRegister>.Create;
    for i := 0 to Length(ins.regs_written) - 1 do
       regs_write.Add(ins.regs_written[i]);

    Result := regs_write;
end;

Function TDeadCode.GetIndex(const AArray : TArray<TIstruzione> ;const Address: UInt64; const StartIndex : Integer; var FoundIndex : Integer ): boolean;
var
  i: integer;
begin
    FoundIndex := -1;
    for i := StartIndex to High(AArray) do
    begin
        if Address = AArray[i].address then
         begin
             FoundIndex := i;
             Exit(true);
         end;
    end;
    result := false;
end;

Function TDeadCode.IsContiene(const AArray: array of x86_insn ;const ANumber: Mnemonics ): boolean;
var
  i: integer;
begin
    for i := Low(AArray) to High(AArray) do
      if ANumber = Mnemonics( AArray[i] ) then
        Exit(true);
    result := false;
end;

function TDeadCode.IsOverwritten(ins: TIstruzione; exp_insn:TArray<TExplicitInstruction>;idxStart : Integer = 0): Boolean;
var
  RegsWrite,
  to_keep : TArray<TRegister>;
  i       : TExplicitInstruction;
  w       : TRegister;
  ind     : Integer;
begin
    RegsWrite := ins.regs_written;

    for ind := 0 to Length(exp_insn) - 1 do
    begin
        if ind+(idxStart) > High(exp_insn) then  Break;

        i := exp_insn[ ind+(idxStart) ];

        // jmp blocca e presume che l'istruzione non venga sovrascritta
        if (i.ins.opcode.mnem =  Mnemonics(X86_INS_JMP)) and (i.ins.operands[0].Tipo = T_IMM) then
            Exit(False);

        SetLength(to_keep,0);
        for w in RegsWrite do
        begin
             if i.reads(w) = True then   Exit( False  );

             if i.IsOverwrites(w) = False then   to_keep := to_keep + [ w ];
        end;
        RegsWrite := to_keep;

        if Length(RegsWrite) = 0 then
           Exit( True )

    end;
    
    Result := False ;
end;

// Determine if an instruction is a memory instruction
function TDeadCode.isMemInsn(ins: TIstruzione): Boolean;
begin
    Result :=  (ins.isMemoryRead) or (ins.isMemoryWrite) ;

    if (ins.opcode.mnem =  Mnemonics(X86_INS_JMP)) and  (ins.operands[0].Tipo = T_MEM) then  Result := True;

    if (ins.opcode.mnem =  Mnemonics(X86_INS_CALL)) and  (ins.operands[0].Tipo = T_MEM) then  Result := True;

end;

function TDeadCode.DeadCodeNop(const block: TArray<TIstruzione>; var Res: TArray<TIstruzione>): Boolean;
var
  index,i,
  Count   : Integer;

  {0xB64D90: cmp dl, 00
   0xB64D93: je 0xB64DA5
   0xB64D9E: jmp 0xB64DA5
   0xB64DA5: or dword ptr [ebp+0xE2], 0x44A7FFDB}
  function IsJccNop: Boolean;
  begin
      Result := False;
      if (block[index].opcode.mnem = Ord(X86_INS_CMP)) and  (IsContiene(JCC_OP,block[index+1].opcode.mnem)) and(block[index+2].opcode.mnem = Ord(X86_INS_JMP)) then
      begin
          if (block[index].operands[1].Tipo = T_IMM) and  (block[index].operands[1].imm.Value = 0) then
          begin
              if (block[index+1].operands[0].imm.Value = block[index+2].operands[0].imm.Value) and (block[index+3].address = block[index+1].operands[0].imm.Value ) then
              begin
                  Exit(True)
              end;
          end;

      end;
  end;

begin
    Result := False;

    index := 0;
    Count := 0;
    try
      while index <= High(block) do
      begin
          if IsJccNop then
          begin
              Result := True;
              for i := 0 to 2 do
              begin
                  DebugMsg('[DeadCodeNopJCC] - Deleting Instruz.  :'+ Res[index].ToString);
                  DeleteRef(Res,index,Modo);
                  Delete(Res,index,1);
              end;
              Continue;
          end
          else if block[index].isNop = False then
          begin
              Inc(Count)
          end
          else begin
              Result := True;
              DebugMsg('[DeadCodeNop] - Deleting Instruz.  :'+ Res[index].ToString);
              DeleteRef(Res,index,Modo);
              Delete(Res,index,1);
              Continue;
          end;

          inc(index);
      end;
    except
       ShowMessage('[DeadCodeNop] - Eroor on Processing Item n.°:'+IntToHex(Count));
    end;
end;

function TDeadCode.DeadCodeReg(const block: TArray<TIstruzione>; var Res: TArray<TIstruzione>): Boolean;
var
  exp_insn: TArray<TExplicitInstruction>;
  ex        : TExplicitInstruction ;
  x,y,Count : Integer;
begin
    Result := False;

    SetLength(exp_insn,0);
    for y := 0 to High(block) do
            exp_insn := exp_insn + [ TExplicitInstruction.Create(readRegs(block[y]), writeRegs(block[y]), block[y]) ];

    x := 0;
    Count := 0;
    while x <= High(exp_insn) do
    begin
        ex := exp_insn[x];

        {$IFDEF TESTING}DebugMsg('[DeadCodeReg] - Linea ' +IntToStr(x)+' :'+ ex.ins.ToString); {$ENDIF}

        try
          // Se fa parte degli opCode da non eliminare mantiene istruzione
          if IsContiene(whitelisted, ex.ins.opcode.mnem) then
               inc(count)
          // Se si tratta di una istruzione che ha operandi di tipo mem o non è sovrascitta allora la mantiene
          else if (isMemInsn(ex.ins) = True) or (IsOverwritten(ex.ins, exp_insn,x+1) = False) then
               inc(count)
          // altrimenti l'istruzione viene cancellata
          else begin
               Result := True ;
               DebugMsg('[DeadCodeReg] - Deleting Instruz.  :'+ Res[x].ToString);

               DeleteRef(Res,x,Modo);
               Delete(Res,x,1);
               Delete(exp_insn,x,1);
               Continue;
          end;
        except
          ShowMessage('[DeadCodeReg] - Eroor on Processing Item n.°:'+IntToHex(Count));
        end;

       inc(x);
    end;
end;

function TDeadCode.DeadCodeMem(const block: TArray<TIstruzione>; var Res: TArray<TIstruzione>): Boolean;
var
  exp_insn: TArray<TExplicitInstruction>;
  ex      : TExplicitInstruction ;
  x,y,
  FoundIdx: Integer;
  idxArray: TArray<Integer>;
  rReg    : TRegister;
  bCFold  : Boolean;

  function IsTestEflag(StartIdx: Integer):Boolean;
  begin
      Result := False;
      if (ex.ins.operands[1].imm.Value in [$1,$4,$40,$80])  then
      begin
        if IsContiene(JCC_OP, exp_insn[StartIdx+1].ins.opcode.mnem)  then
           Result := True;
      end
      else if (ex.ins.operands[1].imm.Value = $800) and (StartIdx > 0) then
      begin
        if (exp_insn[StartIdx+1].ins.opcode.mnem =  Mnemonics(X86_INS_JMP)) or
                             (IsContiene(JCC_OP, exp_insn[StartIdx-1].ins.opcode.mnem))  then
           Result := True;
      end;
  end;

  function IsSafeMnem(registro : TRegister;StartIdx: Integer):Boolean;
  begin
      Result := False;
      // cmp rreg,x ;
      if (ex.Reads(registro)) and (ex.ins.opcode.mnem = Mnemonics(X86_INS_CMP) )then
          Result := True
      // test rreg,rreg
      else if (ex.Reads(registro)) and (ex.ins.opcode.mnem = Mnemonics(X86_INS_TEST) ) and (ex.ins.operands[0].reg.reg = ex.ins.operands[1].reg.reg) then
          Result := True
   // or  rreg,rreg
   // else if (ex.Reads(registro)) and (ex.ins.opcode.mnem = Mnemonics(X86_INS_OR) ) and (ex.ins.operands[0].reg.reg = ex.ins.operands[1].reg.reg) then
   //     Result := True
      else if (ex.Reads(registro)) and (ex.ins.opcode.mnem = Mnemonics(X86_INS_AND) ) then
          Result := IsTestEflag(StartIdx)
      else if (registro.GetParent = Ord(RSP))  then
          Result := True

  end;

  function IsLoop(Istr: TIstruzione): Boolean;
  var
   refFrom : UInt64;
   k       : Integer;
  begin
      Result := False;
      if (y + 1) > High(exp_insn) then Exit;

      refFrom := exp_insn[y+1].ins.address;

      for k := 0 to High(exp_insn) do
      begin
           if Istr.refTo = exp_insn[k].ins.address then
           begin
               if exp_insn[k+1].ins.refTo = refFrom then
                     Result := True;
               Break;
           end;
      end;
  end;

begin
    Result := False;
    bCFold := False;

    SetLength(exp_insn,0);
    for y := 0 to High(block) do
            exp_insn := exp_insn + [ TExplicitInstruction.Create(readRegs(block[y]), writeRegs(block[y]), block[y]) ];

    x := 0;
    while x <= High(exp_insn) do
    begin
        ex := exp_insn[x];

        DebugMsg('[DeadCodeMem] - Linea ' +IntToStr(x)+' :'+ ex.ins.ToString);

        if ex.ins.address = $CCCCAAAA then
        begin
            bCFold := True;
            idxArray := idxArray + [ x ] ;
            inc(x);
            Continue;
        end;

        if bCFold then
        begin
              // eliminare tutta la lista
              for y := High(idxArray) downto 0 do
              begin
                  Result := True;
                  DebugMsg('[DeadCodeMem] - Deleting Instruz.  :'+ Res[idxArray[y]].ToString);
                  DeleteRef(Res,idxArray[y],FModo);
                  Delete(Res,idxArray[y],1);
                  Delete(exp_insn,idxArray[y],1);
              end;
              if Length(idxArray) > 0 then
              begin
                  SetLength(idxArray,0);
              end;

        end;

        bCFold := False;

        try
          if (not IsContiene(ExList, ex.ins.opcode.mnem)) And (IsMemInsn(ex.ins) = False) and (ex.ins.operands[0].Tipo = T_REG)   then
          begin
              SetLength(idxArray,0);
              rReg := ex.ins.operands[0].reg;

              if IsSafeMnem(rReg,x) then
              begin
                  inc(x);
                  Continue;
              end;

              idxArray := idxArray + [ x ] ;

              if (x + 1) > High(exp_insn) then
              begin
                  inc(x);
                  Continue;
              end;

              y := x+1;
              while  y <= High(exp_insn) do
              begin
                  ex := exp_insn[y];

                  DebugMsg('[DeadCodeMem] - Sub Istruz  :'+ ex.ins.ToString);

                  if IsSafeMnem(rReg,y) then
                  begin
                       SetLength(idxArray,0);
                       Break;
                  end;
                  // stop verifica trovato uso in memoria
                  if IsMemInsn(ex.ins) and  ( (ex.Reads(rReg)) or (ex.Writes(rReg)) )then
                  begin
                       if (ex.ins.operands[1].Tipo = T_MEM) and (ex.ins.opcode.mnem = Mnemonics(X86_INS_MOV) ) and (rReg.GetParent <> ex.ins.operands[1].mem.base.GetParent)and (rReg.GetParent <> ex.ins.operands[1].mem.index.GetParent)then
                       begin
                            // se è il caso di mov reg, 0 si deve lascire altrimenti genera problemi
                            if (Length(idxArray) = 1) and (exp_insn[ idxArray[0] ].ins.opcode.mnem = Mnemonics(X86_INS_MOV)) and (exp_insn[ idxArray[0] ].ins.operands[1].Tipo = T_IMM) and (exp_insn[ idxArray[0] ].ins.operands[1].imm.Value = 0)then
                                SetLength(idxArray,0);
                            Break;
                       end;

                       SetLength(idxArray,0);
                       Break;
                  end
                  // Verifica Safe Istruzione ;
                  else if (y+1 <= High(exp_insn)) and (IsSafeMnem(rReg,x)) and (IsContiene(JCC_OP, exp_insn[y+1].ins.opcode.mnem)) and (exp_insn[y+1].ins.operands[0].Tipo = T_IMM)then
                  begin
                      SetLength(idxArray,0);
                      Break;
                  end
                  else if (ex.ins.opcode.mnem =  Mnemonics(X86_INS_JMP))  then
                  begin
                      if (ex.ins.operands[0].Tipo = T_IMM)  then
                      begin
                          // deve continuare la verifica  dalla destinazione del salto in giù
                          if GetIndex(Res,Res[y].refTo,y,FoundIdx) then
                          begin
                              y := FoundIdx;
                              Continue;
                          end else
                          // se non trovato a meno di errori e casi da valutare(long code) è un loop
                          begin
                             SetLength(idxArray,0);
                          end;
                      end
                      else if (ex.ins.operands[0].Tipo = T_REG) then
                      begin
                          if ex.Reads(rReg) then
                             SetLength(idxArray,0);
                      end;
                      Break;
                  end
                  // cambio registro
                  else if ex.ins.operands[1].reg.GetParent = rReg.GetParent then
                  begin
                      rReg     := ex.ins.operands[0].reg;
                      SetLength(idxArray,0);
                      idxArray := idxArray + [ y ] ;
                  end
                  // registro letto o scritto
                  else if ( (ex.Reads(rReg)) or (ex.Writes(rReg)) )then
                  begin
                      if (ex.ins.opcode.mnem =  Mnemonics(X86_INS_POP)) then Break;
                      if (ex.ins.opcode.mnem =  Mnemonics(X86_INS_PUSH)) then
                      begin
                          SetLength(idxArray,0);
                          Break;
                      end
                      // solo sovrascitto non letto( es. add eax, ebx non accettata
                      else if (ex.IsOverwrites(rReg)) and (ex.Reads(rReg) = False) then
                      begin
                          Break;
                      end;

                      idxArray := idxArray + [ y ] ;
                  end
                  else if ( IsContiene([X86_INS_JMP]{JCC_OP}, ex.ins.opcode.mnem) and  (ex.ins.operands[0].Tipo = T_IMM)) or
                          (ex.ins.opcode.mnem =  Mnemonics(X86_INS_RET)) then
                  begin
                      Break;
                  end;

                  inc(y);
              end;

              // eliminare tutta la lista
              for y := High(idxArray) downto 0 do
              begin
                  Result := True;
                  DebugMsg('[DeadCodeMem] - Deleting Instruz.  :'+ Res[idxArray[y]].ToString);
                  DeleteRef(Res,idxArray[y],FModo);
                  Delete(Res,idxArray[y],1);
                  Delete(exp_insn,idxArray[y],1);
              end;
              if Length(idxArray) > 0 then
              begin
                  SetLength(idxArray,0);
                  Continue;
              end;

          end;
        except
          Exception.Create('Errore DeadCodeMem'+IntToStr(x));
        end;
        inc(x);
    end;

end;

function TDeadCode.DeadCode(var block: TArray<TIstruzione>): Boolean;
var
  simplified : Boolean;
begin
    Result := False;

    simplified := DeadCodeReg(block, block);
    if simplified then Result := True;

    simplified := DeadCodeNop(block, block);
    if simplified then Result := True;
end;

end.
