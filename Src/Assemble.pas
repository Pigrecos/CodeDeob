unit Assemble;

interface
   uses System.SysUtils,StrUtils,Winapi.Windows,Capstone,CapstoneApi,CapstoneX86, CodeGen, Nasm_Def,Collections.LinkedList,
        ACTypes;

const
  JCC_OP   : array[0..21] of x86_insn =( X86_INS_CALL,X86_INS_JMP, X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ,
                                         X86_INS_JE,  X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JMP,  X86_INS_JNE,
                                         X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ,X86_INS_JS ) ;


   function ACAssemble(text : AnsiString;  Instruction: TIstruzione ; mode : Integer = CP_MODE_32): TIstruzione;
   function ACAssembleCpuI(text : AnsiString;  Instruction: TIstruzione; mode : Integer = CP_MODE_32): TCpuIstruz;overload;
   function ACAssembleCpuI(text : AnsiString;  Instruction: TCpuIstruz; mode : Integer = CP_MODE_32): TCpuIstruz; overload;
   function FileToSimbolicI(const sFile : String; var modo : Byte ): TArray<TIstruzione>;
   function FileToListDisAsm(const sFile : String; var modo : Byte): TLinkedList<TCpuIstruz>;
   procedure DeleteRef(var List: TArray<TIstruzione>;DelRef: Integer; Modo : Byte);

implementation

Function IsContiene(const AArray: array of x86_insn ;const ANumber: Mnemonics ): boolean;
var
  i: integer;
begin
    for i := Low(AArray) to High(AArray) do
      if ANumber = Mnemonics( AArray[i] ) then
        Exit(true);
    result := false;
end;

function removeLeadingZeros(const Value: string): string;
var
  i: Integer;
begin
  for i := 1 to Length(Value) do
    if Value[i]<>'0' then
    begin
      Result := Copy(Value, i, MaxInt);
      exit;
    end;
  Result := '';
end;

procedure DeleteRef(var List: TArray<TIstruzione>;DelRef: Integer; Modo : Byte);
var
 rRefFrom : TArray<TRef>;
 i,j,RefTo: Integer;
 newRef   : UInt64;
 newIstr  : TIstruzione;
 isDelJcc : Boolean;
begin
    //rRefFrom := List[DelRef].refFrom;
    rRefFrom := [];
    for i := 0 to High(List[DelRef].refFrom) do
     rRefFrom := rRefFrom + [ List[DelRef].refFrom[i] ] ;

    isDelJcc := IsContiene( JCC_OP, Ord(List[DelRef].opcode.mnem));

    for i := 0 to High(List) do
    begin
         j := 0;
         while j <= High(List[i].refFrom) do
         begin
             // Modifica Referenza
             RefTo :=  List[i].refFrom[j].idxRefTo;

             if isDelJcc then
             begin
                 if List[i].refFrom[j].idxRefTo =  DelRef then
                 begin
                     Delete(List[i].refFrom,j,1) ;
                     Continue;
                 end;
             end;

             if RefTo > DelRef then
                List[i].refFrom[j].idxRefTo := RefTo - 1;

             inc(j);
         end;
    end;

    // update istruction
    newRef := List[ DelRef + 1 ].address;
    for i := 0 to High(rRefFrom) do
    begin
        // aggiungo referenza alla istruzione successiva
        List[ DelRef + 1 ].refFrom :=  List[ DelRef + 1 ].refFrom + [ List[DelRef].refFrom[i] ];

        // Modifica Referenza in caso di jcc
        RefTo :=  rRefFrom[i].idxRefTo;

        // verifica che la reference sia valida e sia un jcc
        if  not IsContiene( JCC_OP, Ord(List[RefTo].opcode.mnem))  then
          continue;

        newIstr := ACAssemble(AnsiString(List[RefTo].opcode.ToString) + ' 0x'+ fIntToHex(newRef), List[RefTo],Modo);
        newIstr.refTo   := newRef;
        newIstr.refFrom := List[RefTo].refFrom;
        List[RefTo]     := newIstr;
    end;

end;

function ACAssemble(text : AnsiString;  Instruction: TIstruzione ; mode : Integer = CP_MODE_32): TIstruzione;
var
  Res     : TIstruzione;
  CG      : TCodeGen;
  cDisAsm : TCapstone;
  stmp    : AnsiString;
  imm,imm1: string;
  SpliS   : TArray<String>;
  Mask,
  addr    : UInt64;

  function GetMask(sValue: string): UInt64;
  var
    Len : Integer;
    z   : Integer;
  begin
      Result := 0;
      Len := Length(sValue);
      for z := 0 to Len -1 do
          Result := (Result shl 4) or $F
  end;

begin
    if   mode = CP_MODE_32 then mode := CS_MODE_32
    else                        mode := CS_MODE_64;

    addr := Instruction.address;

    if Length(text) < 3 then
        raise Exception.Create('Asm Command not valid: '+text);

    res := TIstruzione.Create(Ord(X86_INS_NOP));
    CG  := TCodeGen.Create(mode,MASM_SYNTAX);
    try
      if CG.Pi_Asm(addr,PAnsiChar(text)) > 0 then
      begin
          cDisAsm      := TCapstone.Create;
          cDisAsm.Mode := mode;
          cDisAsm.Open;
          try
            if cDisAsm.Disassemble(addr , CG.Encode) then
            begin
                Res       := Res.FromCpuIstruzione(cDisAsm.Insn);
                Res.isNop := cDisAsm.IsNop;

                Res.refFrom := Res.refFrom + instruction.refFrom;
                Res.refTo   := instruction.refTo;

                // per la gestione dei movabs valori con segno o maggiori di dword nelle operazioni!!!!!
                if (mode =  CS_MODE_64) and (cDisAsm.Insn.operands[1].Tipo = T_IMM) then
                begin
                    SpliS := string(text).Split([',']);
                    imm1 := removeLeadingZeros(Trim( StringReplace(SpliS[1],'0x','',[rfReplaceAll] )));
                    imm  := removeLeadingZeros( string(fIntToHex(cDisAsm.Insn.operands[1].imm.S)));

                    if imm1 <> imm then
                    begin
                        Mask := GetMask(imm1);
                        Res.operands[1].imm.Value := StrToInt64('$'+imm1) and Mask;
                    end;
                end;
            end else
            begin
                stmp := 'failed! on Disassemble : '+ text;
                MessageBoxA(0,PAnsiChar(stmp),'Info',MB_OK);
            end;

            cDisAsm.Close;
          finally
            cDisAsm.Free
          end;

      end else
      begin
          stmp := 'failed! on Assembly : '+ text;
          MessageBoxA(0,PAnsiChar(stmp),'Info',MB_OK);
      end;
    finally
       CG.Free;

    end;

    Result := Res;
end;

function ACAssembleCpuI(text : AnsiString;  Instruction: TCpuIstruz; mode : Integer = CP_MODE_32): TCpuIstruz;
var
  tmpIstr : TIstruzione;
begin
    tmpIstr := TIstruzione.Create(Ord(X86_INS_NOP));
    tmpIstr.address := Instruction.address;

    tmpIstr.refFrom := tmpIstr.refFrom + Instruction.refFrom;
    tmpIstr.refTo   := Instruction.refTo;

    Result := ACAssembleCpuI(text, tmpIstr, mode)
end;

function ACAssembleCpuI(text : AnsiString;  Instruction: TIstruzione; mode : Integer = CP_MODE_32): TCpuIstruz;
var
  CG      : TCodeGen;
  cDisAsm : TCapstone;
  stmp    : AnsiString;
  addr    : UInt64;
begin
    if   mode = CP_MODE_32 then mode := CS_MODE_32
    else                        mode := CS_MODE_64;

    addr := Instruction.address;

    CG  := TCodeGen.Create(mode,MASM_SYNTAX);
    try
      if CG.Pi_Asm(addr,PAnsiChar(text)) > 0 then
      begin
          cDisAsm      := TCapstone.Create;
          cDisAsm.Mode := mode;
          cDisAsm.Open;
          try
            if cDisAsm.Disassemble(addr , CG.Encode) then
            begin
                Result := cDisAsm.Insn;

                Result.refFrom := Result.refFrom + instruction.refFrom;
                Result.refTo   := instruction.refTo;
            end else
            begin
                stmp := 'failed! on Disassemble : '+ text;
                MessageBoxA(0,PAnsiChar(stmp),'Info',MB_OK);
            end;

            cDisAsm.Close;
          finally
            cDisAsm.Free
          end;

      end else
      begin
          stmp := 'failed! on Assembly : '+ text;
          MessageBoxA(0,PAnsiChar(stmp),'Info',MB_OK);
      end;
    finally
       CG.Free;
    end;

end;

function FileToSimbolicI(const sFile : String; var modo : Byte): TArray<TIstruzione>;
var
  CG     : TCodeGen;
  cDisAsm: TCapstone;
  Res    : TIstruzione;
  vAsm   : TTAssembled;
  ofs    : UInt64;
  i      : Integer;
begin
    SetLength(Result,0);
    ofs := 0;

    CG  := TCodeGen.Create(CS_MODE_32,MASM_SYNTAX);
    try
      if CG.Assembly_File(sFile,vAsm,ofs)  then
      begin
          cDisAsm      := TCapstone.Create;
          if CG.Modo = PI_MODO_32 then cDisAsm.Mode := CS_MODE_32
          else                         cDisAsm.Mode := CS_MODE_64;

          modo := CG.Modo;

          cDisAsm.Open;
          try
            for i := 0 to  Length(vAsm) - 1 do
            begin
                if cDisAsm.Disassemble(vAsm[i].Address , vAsm[i].Bytes) then
                begin
                    Res       := Res.FromCpuIstruzione(cDisAsm.Insn);
                    Res.isNop := cDisAsm.IsNop;

                    Result:= Result + [Res];
                end else
                    MessageBoxA(0,'Info','disasm failed!',MB_OK);
            end;

            cDisAsm.Close;
          finally
            cDisAsm.Free
          end;
      end else
          MessageBoxA(0,'Info','Assemble failed!',MB_OK);
    finally
      CG.Free;
    end;

end;

function FileToListDisAsm(const sFile : String; var modo : Byte): TLinkedList<TCpuIstruz>;
var
  CG     : TCodeGen;
  cDisAsm: TCapstone;
  vAsm   : TTAssembled;
  ofs    : UInt64;
  i      : Integer;
begin

    ofs := 0;

    CG     := TCodeGen.Create(CS_MODE_32,MASM_SYNTAX);
    Result := TLinkedList<TCpuIstruz>.Create;
    try
      if CG.Assembly_File(sFile,vAsm,ofs)  then
      begin
          cDisAsm      := TCapstone.Create;
          if CG.Modo = PI_MODO_32 then cDisAsm.Mode := CS_MODE_32
          else                         cDisAsm.Mode := CS_MODE_64;

          modo := CG.Modo;

          cDisAsm.Open;
          try
            for i := 0 to  Length(vAsm) - 1 do
            begin
                if cDisAsm.Disassemble(vAsm[i].Address , vAsm[i].Bytes) then
                begin
                    Result.AddLast(cDisAsm.Insn);
                end else
                    MessageBoxA(0,'Info','disasm failed!',MB_OK);
            end;

            cDisAsm.Close;
          finally
            cDisAsm.Free
          end;
      end else
          MessageBoxA(0,'Info','Assemble failed!',MB_OK);
    finally
      CG.Free;
    end;
end;

end.
