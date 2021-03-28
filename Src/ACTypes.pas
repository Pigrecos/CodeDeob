unit ACTypes;

interface
   uses System.SysUtils,Winapi.Windows,System.Generics.Collections,Capstone,CapstoneApi,CapstoneX86,superobject,
   System.StrUtils, System.Types;

type
  TStato = record
  end;

  Mnemonics = Integer;
  TCompare<T>= Reference to function(const a,b: T; var state : TStato):Boolean;

  TMultiOp = record
   nOp     : Byte;
   OpCodes : TArray<Mnemonics>;
  end;

  TOpCode = record
    mnem   : Mnemonics;
    compare: TCompare<TOpCode>;

    function Equals(const other:TOpCode; var state: TStato): Boolean;
    function ToString: string;
    class operator Explicit(pCompare : TCompare<TOpCode>): TOpCode;
    class operator Explicit(pMnem: Mnemonics): TOpCode;
  end;

  TImmediate = record
    Value   : Int64;
    compare: TCompare<TImmediate>;

    function Equals(const other:TImmediate; var state: TStato): Boolean;
    function ToString: string;
    class operator Explicit(pCompare : TCompare<TImmediate>):TImmediate;
    class operator Explicit(pValue: Int64): TImmediate;
  end;

  TSegment = record
    seg    : TSegments;
    compare: TCompare<TSegment>;

    function Equals(const other:TSegment; var state: TStato): Boolean;
    function ToString: string;
    class operator Explicit(pCompare : TCompare<TSegment>):TSegment;
    class operator Explicit(pSeg: TSegments): TSegment;
  end;

  TRegister = record
  private

   public
    reg    : TRegisters;
    compare: TCompare<TRegister>;

    function Equals(const other:TRegister; var state: TStato): Boolean;
    function ToString: string;
    class operator Explicit(pCompare : TCompare<TRegister>):TRegister;
    class operator Explicit(pReg: TRegisters): TRegister;

    function Size: Integer;
    function OffSet: Integer;
    function GetParent: Integer;
    function GetReg(regParent: Integer; rSize: Byte): TRegisters;
  end;

  TMemoria = record
    seg    : TSegment;
    base   : TRegister;
    index  : TRegister;
    scale  : TImmediate;
    disp   : TImmediate;
    compare: TCompare<TMemoria>;

  public
    constructor Memoria(vSeg : TSegment; vBase, vIndex: TRegister; vScale, vDisp: TImmediate);overload;
    constructor Memoria(vBase, vIndex: TRegister; vScale, vDisp: TImmediate);overload;
    constructor Memoria(vDisp: TImmediate);overload;
    function ToString: string;
    class operator Explicit(pCompare : TCompare<TMemoria>):TMemoria;
    function Equals(const other:TMemoria; var state: TStato): Boolean;
  end;

  TOperandTipo = TCpuOperandTipo ;
  TOperand = record
    Tipo   : TOperandTipo;
    reg    : TRegister;
    imm    : TImmediate;
    mem    : TMemoria;
    Size   : TImmediate;
    Access : UInt8;
    compare: TCompare<TOperand>;

    function ToString: string;
    class operator Explicit(pCompare : TCompare<TOperand>):TOperand;
    class operator Explicit(pRegs : TRegisters): TOperand;
    class operator Explicit(pReg  : TRegister): TOperand;
    class operator Explicit(pValue: TImmediate): TOperand;
    class operator Explicit(pMem  : TMemoria)  : TOperand;
    class operator Equal(a,b:TOperand)  : Boolean;
    function Equals(const other:TOperand; var state: TStato): Boolean;
    function LoadFromJson(const OperandJO: TSuperArray;var sStato: TStato): TArray<TOperand>;
    function LoadReplFromJson(const OperandJO: TSuperArray; var sStato: TStato): TArray<TOperand>;
    function isMemoryRead: Boolean;
    function isMemoryWrite: Boolean;
  private

  end;

  TIstruzione = record
    opcode       : TOpcode;
    opCount      : Integer;
    operands     : array[0..3] of TOperand;
    isNop        : Boolean;
    regs_read    : TArray<TRegister>;
    regs_written : TArray<TRegister>;
    groups       : TArray<UInt8>;
    prefix       : array[0..3] of UInt8;
    address      : UInt64 ;
    size         : UInt16;
    bytes        : array[0..15] of UInt8;
    eflags       : UInt64;
    compare      : TCompare<TIstruzione>;
    {$IFDEF DEBUG} Istr_Str : string; {$ENDIF}

    refFrom      : TArray<TRef>;
    refTo        : UInt64;

   private
    function  GetOperand(Index: Integer): TOperand;
    procedure SetOperand(Index: Integer; const Value: TOperand);
   public
    function ToString(PrintAddr: Boolean= False): string;
    function FromCpuIstruzione(const insn : TCpuIstruz):TIstruzione;
    function isMemoryRead: Boolean;
    function isMemoryWrite: Boolean;
    function Equals(var other:TIstruzione; var state: TStato): Boolean;
    function LoadFromJson(const instrJO: TSuperArray; var sStato: TStato; var aMnem  : TMultiOp; lRepl : Boolean = False): TArray<TIstruzione>;
    class operator Explicit(pcompare: TCompare<TIstruzione>): TIstruzione;
    constructor Create(mnem : Mnemonics; vOpCount : Integer = 0);overload;
    constructor Create(mnem : Mnemonics; op1, op2, op3, op4: TOperand); overload;
    constructor Create(mnem : Mnemonics; op1, op2, op3: TOperand); overload;
    constructor Create(mnem : Mnemonics; op1, op2: TOperand); overload;
    constructor Create(mnem : Mnemonics; op1: TOperand); overload;

    property Operando[Index : Integer] : TOperand read GetOperand write SetOperand;
  end;

  function fIntToHex(Value: UInt64): AnsiString;

implementation
       uses System.Character,Convert,ACStato;

function fIntToHex(Value: UInt64): AnsiString;
var
  I,NewLen,I32 : Integer;
begin
    Result := '';
    NewLen := 1;

    I := Value shr 4;
    while I > 0 do
    begin
      Inc(NewLen);
      I := I shr 4;
    end;

    I := NewLen;
    while I mod 2 <> 0 do
      Inc(I);

    if I > NewLen then
    begin
      for I32 := 0 to (I - NewLen) - 1 do
        Result := Result + '0';
    end  ;

    Result := Result + AnsiString(IntToHex(Value,NewLen))

end;

{ TOpCode }

class operator TOpCode.Explicit(pCompare : TCompare<TOpCode>): TOpCode;
var
  c : TOpCode;
begin
   c.compare := pCompare;

   Result := c;
end;

class operator TOpCode.Explicit(pMnem: Mnemonics): TOpCode;
var
  c: TOpCode;
begin
    c.mnem := pMnem;
    Result := c;
end;

function TOpCode.Equals(const other: TOpCode; var state : TStato): Boolean;
begin
    if Assigned(compare)       then  Exit( compare(Self,other,state));
    if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

    Result := mnem = other.mnem;
end;

function TOpCode.ToString: string;
var
 str : string;
begin
    str := gConvert.ins2str(mnem);
    if str = ''  then Result := '?'
    else              Result := str

end;

{ TImmediate }

class operator TImmediate.Explicit(pValue: Int64): TImmediate;
var
  c: TImmediate;
begin
    c.Value := pValue;
    Result  := c;
end;

class operator TImmediate.Explicit(pCompare: TCompare<TImmediate>): TImmediate;
var
  c : TImmediate;
begin
   c.compare := pCompare;

   Result := c;
end;

function TImmediate.Equals(const other: TImmediate; var state: TStato): Boolean;
begin
    if Assigned(compare)       then  Exit( compare(Self,other,state));
    if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

    Result := Value = other.Value;
end;

function TImmediate.ToString: string;

begin
    Result := '';

    if (Value > 9) or (Value < 0)  then  Result := '0x';

    Result := Result + string(fIntToHex(Value) )
end;

{ TSegment }

class operator TSegment.Explicit(pSeg: TSegments): TSegment;
var
  c : TSegment;
begin
    c.seg := pSeg;
    Result:= c;
end;

class operator TSegment.Explicit(pCompare: TCompare<TSegment>): TSegment;
var
  c : TSegment;
begin
   c.compare := pCompare;

   Result := c;
end;

function TSegment.Equals(const other: TSegment; var state: TStato): Boolean;
begin
    if Assigned(compare)       then  Exit( compare(Self,other,state));
    if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

    Result := seg = other.seg;
end;

function TSegment.ToString: string;
begin
    case seg of
     CS: Result :=  'cs';
     SS: Result :=  'ss';
     DS: Result :=  'ds';
     ES: Result :=  'es';
     FS: Result :=  'fs';
     GS: Result :=  'gs';
    else
        Result := '';
    end;
end;

{ TRegister }

class operator TRegister.Explicit(pReg: TRegisters): TRegister;
var
  c : TRegister;
begin
    c.reg := pReg;
    Result:= c;
end;

class operator TRegister.Explicit(pCompare: TCompare<TRegister>): TRegister;
var
  c : TRegister;
begin
   c.compare := pCompare;

   Result := c;
end;

function TRegister.Equals(const other: TRegister; var state: TStato): Boolean;
begin
    if Assigned(compare)       then  Exit( compare(Self,other,state));
    if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

    Result := reg = other.reg;
end;

function TRegister.OffSet: Integer;
begin
    case TRegisters(reg)  of
       AH,
       BH,
       CH,
       DH: Exit(1);
    else
       Exit(0);
    end;
end;

Function TRegister.GetReg(regParent : Integer; rSize : Byte ) : TRegisters;
var
 vReg : TRegisters;
begin
  vReg :=  REG_INVALID;

  case TRegisters(regParent) of
      RAX:begin
              case rSize of
                $1: vReg := AL;
                $20:vReg := AH;
                $2: vReg := AX;
                $4: vReg := EAX;
                $8: vReg := RAX;
              end;
          end;
      RBX:begin
              case rSize of
                $1: vReg := BL;
                $20:vReg := BH;
                $2: vReg := BX;
                $4: vReg := EBX;
                $8: vReg := RBX;
              end;
          end;
      RCX:begin
               case rSize of
                  $1: vReg := CL;
                  $20:vReg := CH;
                  $2: vReg := CX;
                  $4: vReg := ECX;
                  $8: vReg := RCX;
               end;
          end;
      RDX:begin
              case rSize of
                $1: vReg := DL;
                $20:vReg := DH;
                $2: vReg := DX;
                $4: vReg := EDX;
                $8: vReg := RDX;
              end;
          end;
      RSP:begin
              case rSize of
                $1: vReg := SPL;
                $20:vReg := REG_INVALID;
                $2: vReg := SP;
                $4: vReg := ESP;
                $8: vReg := RSP;
              end;
          end;
      RBP:begin
              case rSize of
                $1: vReg := BPL;
                $20:vReg := REG_INVALID;
                $2: vReg := BP;
                $4: vReg := EBP;
                $8: vReg := RBP;
              end;
          end;
      RSI:begin
              case rSize of
                $1: vReg := SIL;
                $20:vReg := REG_INVALID;
                $2: vReg := SI;
                $4: vReg := ESI;
                $8: vReg := RSI;
              end;
          end;
      RDI:begin
              case rSize of
                $1: vReg := DIL;
                $20:vReg := REG_INVALID;
                $2: vReg := DI;
                $4: vReg := EDI;
                $8: vReg := RDI;
              end;
          end;
      R8: begin
              case rSize of
                $1: vReg := R8B;
                $20:vReg := REG_INVALID;
                $2: vReg := R8W;
                $4: vReg := R8D;
                $8: vReg := R8;
              end;
          end;
      R9: begin
              case rSize of
                $1: vReg := R9B;
                $20:vReg := REG_INVALID;
                $2: vReg := R9W;
                $4: vReg := R9D;
                $8: vReg := R9;
              end;
          end;
      R10:begin
               case rSize of
                 $1: vReg := R10B;
                 $20:vReg := REG_INVALID;
                 $2: vReg := R10W;
                 $4: vReg := R10D;
                 $8: vReg := R10;
               end;
          end;
      R11:begin
              case rSize of
                 $1: vReg := R11B;
                 $20:vReg := REG_INVALID;
                 $2: vReg := R11W;
                 $4: vReg := R11D;
                 $8: vReg := R11;
              end;
          end;
      R12:begin
              case rSize of
                $1: vReg := R12B;
                $20:vReg := REG_INVALID;
                $2: vReg := R12W;
                $4: vReg := R12D;
                $8: vReg := R12;
              end;
          end;
      R13:begin
              case rSize of
                $1: vReg := R13B;
                $20:vReg := REG_INVALID;
                $2: vReg := R13W;
                $4: vReg := R13D;
                $8: vReg := R13;
              end;
          end;
      R14:begin
              case rSize of
                $1: vReg := R14B;
                $20:vReg := REG_INVALID;
                $2: vReg := R14W;
                $4: vReg := R14D;
                $8: vReg := R14;
              end;
          end;
      R15:begin
              case rSize of
                $1: vReg := R15B;
                $20:vReg := REG_INVALID;
                $2: vReg := R15W;
                $4: vReg := R15D;
                $8: vReg := R15;
              end;
          end;
  end;
	Result := vReg;
end;

function TRegister.GetParent: Integer;
begin
    Result := Ord(REG_INVALID);

    case TRegisters(reg) of
     RAX,EAX, AX, AH, AL : Result := Ord(RAX);
     RBX,EBX, BX, BH, BL : Result := Ord(RBX);
     RCX,ECX, CX, CH, CL : Result := Ord(RCX);
     RDX,EDX, DX, DH, DL : Result := Ord(RDX);
     RBP,EBP, BP, BPL    : Result := Ord(RBP);
     RSP,ESP, SP, SPL    : Result := Ord(RSP);
     RSI,ESI, SI, SIL    : Result := Ord(RSI);
     RDI,EDI, DI, DIL    : Result := Ord(RDI);

     R8 , R8D, R8W, R8B    : Result := Ord(R8);
     R9 , R9D, R9W, R9B    : Result := Ord(R9);
     R10 ,R10D,R10W,R10B   : Result := Ord(R10);
     R11 ,R11D,R11W,R11B   : Result := Ord(R11);
     R12 ,R12D,R12W,R12B   : Result := Ord(R12);
     R13 ,R13D,R13W,R13B   : Result := Ord(R13);
     R14 ,R14D,R14W,R14B   : Result := Ord(R14);
     R15 ,R15D,R15W,R15B   : Result := Ord(R15);
    end;
end;

function TRegister.Size: Integer;
begin
     case TRegisters(reg) of
        RAX,
        RBX,
        RCX,
        RDX,
        RBP,
        RSP,
        RSI,
        RDI,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15:  Exit(SizeOf(UInt64));
        EAX,
        EBX,
        ECX,
        EDX,
        EBP,
        ESP,
        ESI,
        EDI,
        R8D,
        R9D,
        R10D,
        R11D,
        R12D,
        R13D,
        R14D,
        R15D: Exit(SizeOf(UInt32));
        AX,
        BX,
        CX,
        DX,
        BP,
        SP,
        SI,
        DI,
        R8W,
        R9W,
        R10W,
        R11W,
        R12W,
        R13W,
        R14W,
        R15W: Exit(SizeOf(UInt16));
        AH,
        AL,
        BH,
        BL,
        CH,
        CL,
        DH,
        DL,
        BPL,
        SPL,
        SIL,
        DIL,
        R8B,
        R9B,
        R10B,
        R11B,
        R12B,
        R13B,
        R14B,
        R15B: Exit(SizeOf(UInt8));
     end;
     Result := 0;
end;

function TRegister.ToString: string;
var
 str : string;
begin
    str := gConvert.reg2str(reg);
    if str = ''  then Result := '?'
    else              Result := str
end;

{ TMemoria }

constructor TMemoria.Memoria(vSeg: TSegment; vBase, vIndex: TRegister; vScale,vDisp: TImmediate);
begin
    ZeroMemory(@Self, SizeOf(TMemoria));
    seg  := vSeg;
    base := vBase;
    index:= vIndex;
    scale:= vScale;
    disp := vDisp;
end;

constructor TMemoria.Memoria(vBase, vIndex: TRegister; vScale, vDisp: TImmediate);
begin
    ZeroMemory(@Self, SizeOf(TMemoria));
    base := vBase;
    index:= vIndex;
    scale:= vScale;
    disp := vDisp;
end;

constructor TMemoria.Memoria(vDisp: TImmediate);
begin
    ZeroMemory(@Self, SizeOf(TMemoria));
    disp := vDisp;
end;

class operator TMemoria.Explicit(pCompare: TCompare<TMemoria>): TMemoria;
var
  c : TMemoria;
begin
    ZeroMemory(@c, SizeOf(TMemoria));
    c.Compare := pCompare;

    Result := c;
end;

function TMemoria.Equals(const other: TMemoria; var state: TStato): Boolean;
begin
    if Assigned(compare)       then  Exit( compare(Self,other,state));
    if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

    Result :=  (seg.Equals(other.seg, state))     and
               (base.Equals(other.base, state))   and
               (index.Equals(other.index, state)) and
               (scale.Equals(other.scale, state)) and
               (disp.Equals(other.disp, state));
end;

function TMemoria.ToString: string;
var
  str,temp,
  operatorText: string;
  prependPlus : Boolean;

begin
    str := '';
    prependPlus := false;

    if base.reg <> REG_INVALID then
    begin
        str      := str + base.ToString;
        prependPlus := true;
    end;
    if index.reg  <> REG_INVALID then
    begin
        if prependPlus then
            str  := str + '+';
        str         := str + index.ToString;
        if scale.Value > 1 then temp := Format('*%s', [scale.ToString])
        else                    temp := '';
        str         := str + temp;
        prependPlus := true;
    end;
    if disp.Value  <> 0 then
    begin
        operatorText := '+';
        if disp.Value < 0 then begin
            operatorText := '-';
             temp    := Format('0x%X', [disp.Value * -1]);
        end
        else
            temp    := Format('0x%X', [disp.Value]);
        if prependPlus then str  := str + operatorText;
        str  := str + temp;
    end;
     Result :=  '['+str+']';

     if seg.seg <> INVALID then
       if seg.ToString <> '' then
           Result := seg.ToString +':' + Result;

end;

{ TOperand }

class operator TOperand.Explicit(pRegs: TRegisters): TOperand;
var
  c : TOperand;
begin
    ZeroMemory(@c, SizeOf(TOperand));
    c := TOperand(TRegister(pRegs));

    Result := c;
end;

class operator TOperand.Explicit(pReg: TRegister): TOperand;
var
  c : TOperand;
begin
  ZeroMemory(@c, SizeOf(TOperand));
  c.Tipo := TOperandTipo(T_REG);
  c.reg  := pReg;

  Result := c;

end;

class operator TOperand.Explicit(pMem: TMemoria): TOperand;
var
  c : TOperand;
begin
        ZeroMemory(@c, SizeOf(TOperand));
    c.Tipo := TOperandTipo(T_MEM);
    c.mem  := pMem;

    Result := c;
end;

function GetRegCreate(lsReg: string;var sStato: TStato):TRegister;
begin
    if      lsReg[1] = '?'      then  Result := TRegister(sStato.RegWild(0))
    else if lsReg[1].IsLetter   then  Result := TRegister(gConvert.str2reg(lsReg))
    else if StrToInt(lsReg) = 0 then  Result := TRegister(REG_INVALID)
    else                              Result := TRegister(sStato.MakeRegisterN(StrToInt(lsReg))) ;
end;

function GetSegCreate(lsSeg: string;var sStato: TStato):TSegment;
begin
    if      lsSeg[1] = '?'      then  Result := TSegment(sStato.SegWild(0))
    else if lsSeg[1].IsLetter   then  Result := TSegment(gConvert.Str2Seg(lsSeg))
    else if StrToInt(lsSeg) = 0 then  Result := TSegment(INVALID)
end;

function GetImmCreate(lsImm: Int64;var sStato: TStato):TImmediate;
begin
    if  lsImm = $CC                    then  Result :=  TImmediate(sStato.ValWild(0))
    else if lsImm  =  -1{per inc/dec}  then  Result :=  TImmediate(lsImm)
    else if lsImm  =  255{per inc/dec} then  Result :=  TImmediate(lsImm)
    else if (lsImm and $FF00) =  $FF00 then  Result :=  TImmediate(lsImm xor $FF00)
    else                                     Result :=  TImmediate(sStato.MakeValueN(lsImm)) ;
end;

function TOperand.LoadReplFromJson(const OperandJO: TSuperArray;var sStato: TStato): TArray<TOperand>;
var
  i,nOp    : Integer;
  oJO,memJO: ISuperObject;
  oOperand : TOperand;
  sTipoOP  : string;
  nMem,
  opSize   : Integer;
  lMem     : TMemoria;

  function GetRegReplCreate(lsReg: Int64):TRegister;
  begin
      Result     := TRegister(sStato.registers[lsReg].tVal) ;
      // per aggirare il problema di non avere ancora i dati reali da sostituire
      Result.reg := TRegisters(lsReg);
  end;

  function GetImmReplCreate(lsImm: Int64):TImmediate;
  begin
      Result      := sStato.values[lsImm].tVal ;
      // per aggirare il problema di non avere ancora i dati reali da sostituire
      Result.Value:= lsImm;
  end;

  function GetMemReplCreate(lsMem: Int64):TMemoria;
  begin
      Result      := sStato.memorys[lsMem].tVal ;
      // per aggirare il problema di non avere ancora i dati reali da sostituire
      Result.base.reg := TRegisters(lsMem);
  end;

  function GetOperandReplCreate(lsOperand: Int64):TOperand;
  begin
      Result      := sStato.operands[lsOperand].tVal ;
      // per aggirare il problema di non avere ancora i dati reali da sostituire
      Result.Tipo    := T_OPERAND;
      Result.reg.reg := TRegisters(lsOperand)
  end;

begin
   SetLength(Result,0);
   //carica tutti gli operandi dell'istruzione
   for i := 0 to OperandJO.Length - 1 do
   begin
       oJO     := OperandJO.O[i];
       ZeroMemory( @oOperand, SizeOf(TOperand));

       sTipoOP := oJO.S['Tipo'];
       opSize  := oJO.I['Size'];

       nOp :=OperandJO.I[i];
       if nOp > 0 then
       begin
           oOperand := GetOperandReplCreate(nOp);
       end
       else if sTipoOP = 'reg' then
       begin
           nMem  := oJO.I['Reg'];
           if nMem > 0 then   oOperand := TOperand( GetRegReplCreate(oJO.I['Reg']) )
           else               oOperand := TOperand( GetRegCreate(oJO.S['Reg'],sStato) )

       end
       else if sTipoOP = 'imm' then
       begin
           nMem  := oJO.I['Imm'];
           // imm in generale
           if (nMem and $FF00) <>  $FF00 then   oOperand := TOperand( GetImmReplCreate(oJO.I['Imm']) )
           else                                 oOperand := TOperand( GetImmCreate(oJO.I['Imm'] ,sStato) )
       end
       else if sTipoOP = 'mem' then
       begin
           memJO := oJO.O['Mem'];
           nMem  := oJO.I['Mem'];
           // memoria in generale
           if nMem > 0 then
               oOperand := TOperand( GetMemReplCreate(oJO.I['Mem']) )
           else begin
                lMem.seg  := GetSegCreate(memJO.S['seg'],sStato);

                nMem  := memJO.I['base'];
                if nMem > 0 then  lMem.base :=  GetRegReplCreate(memJO.I['base'])
                else              lMem.base :=  GetRegCreate(memJO.S['base'],sStato)  ;

                nMem  := memJO.I['index'];
                if nMem > 0 then  lMem.index:=  GetRegReplCreate(memJO.I['index'])
                else              lMem.index:=  GetRegCreate(memJO.S['index'],sStato) ;

                lMem.scale:= GetImmCreate(memJO.I['scale'] or $FF00,sStato);
                lMem.disp := GetImmCreate(memJO.I['disp']  or $FF00,sStato);
                oOperand  := TOperand( lMem.Memoria(lMem.seg, lMem.base, lMem.index, lMem.scale,lMem.disp) );
           end;
       end;
       oOperand.Size.Value := opSize;

       Result := Result + [ oOperand ];
   end;
end;

function TOperand.LoadFromJson(const OperandJO: TSuperArray;var sStato: TStato): TArray<TOperand>;
var
  i,nOp,nMem: Integer;
  oJO,memJO : ISuperObject;
  oOperand  : TOperand;
  lMem      : TMemoria;
  sTipoOP   : string;

begin
   SetLength(Result,0);
   //carica tutti gli operandi dell'istruzione
   for i := 0 to OperandJO.Length - 1 do
   begin
       oJO     := OperandJO.O[i];
       ZeroMemory( @oOperand, SizeOf(TOperand));

       sTipoOP := oJO.S['Tipo'];

       nOp :=OperandJO.I[i];
       if nOp > 0 then
       begin
           oOperand := TOperand(sStato.MakeOperandN(nOp));
       end
       else if sTipoOP = 'reg' then
       begin
           oOperand := TOperand( GetRegCreate(oJO.S['Reg'],sStato) );
       end
       else if sTipoOP = 'imm' then
       begin
           oOperand := TOperand( GetImmCreate(oJO.I['Imm'],sStato) );
       end
       else if sTipoOP = 'mem' then
       begin
           memJO := oJO.O['Mem'];
           nMem  := oJO.I['Mem'];
           // memoria in generale
           if nMem > 0 then
                oOperand := TOperand(TMemoria(sStato.MakeMemoryN(oJO.I['Mem'])))
           else begin
                lMem.seg  := GetSegCreate(memJO.S['seg'],sStato);
                lMem.base := GetRegCreate(memJO.S['base'],sStato);
                lMem.index:= GetRegCreate(memJO.S['index'],sStato);
                lMem.scale:= GetImmCreate(memJO.I['scale'] or $FF00,sStato);
                lMem.disp := GetImmCreate(memJO.I['disp'] or $FF00,sStato);
                oOperand  := TOperand( lMem.Memoria(lMem.seg, lMem.base, lMem.index, lMem.scale,lMem.disp) );
           end;
       end;

       Result := Result + [ oOperand ];
   end;
end;

class operator TOperand.Explicit(pCompare: TCompare<TOperand>): TOperand;
var
  c : TOperand;
begin
   ZeroMemory(@c, SizeOf(TOperand));
   c.Tipo    := TIPO_INVALID;
   c.compare := pCompare;

   Result := c;
end;

class operator TOperand.Explicit(pValue: TImmediate): TOperand;
var
  c : TOperand;
begin
    ZeroMemory(@c, SizeOf(TOperand));
    c.Tipo := TOperandTipo(T_IMM);
    c.imm  := pValue;

    Result := c;

end;

function TOperand.isMemoryRead:Boolean;
begin
    Result := (Tipo = T_MEM) and ( (Access and CS_AC_READ) = CS_AC_READ );
end;

function TOperand.isMemoryWrite:Boolean;
begin
    Result := (Tipo = T_MEM) and ( (Access and CS_AC_WRITE) = CS_AC_WRITE );
end;

class operator TOperand.Equal(a, b: TOperand): Boolean;
begin
    Result := True;

    if a.Tipo <> b.Tipo then Exit(False);

    case  a.Tipo of

      T_REG: begin
                 if a.reg.reg <> b.reg.reg then Exit(False)
             end;
      T_IMM:  begin
                 if a.imm.Value <> b.imm.Value then Exit(False)
             end;
      T_MEM: begin
                 if (a.mem.seg.seg     <> b.mem.seg.seg) or
                    (a.mem.base.reg    <> b.mem.base.reg) or
                    (a.mem.index.reg   <> b.mem.index.reg) or
                    (a.mem.scale.Value <> b.mem.scale.Value) or
                    (a.mem.disp.Value  <> b.mem.disp.Value) then Exit(False)
             end;
    end;
end;

function TOperand.Equals(const other: TOperand; var state: TStato): Boolean;
begin
    Result := False;

    if Assigned(compare)       then  Exit( compare(Self,other,state));
    if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

    if Tipo <> other.Tipo then Exit(False);

    case Tipo of
      TIPO_INVALID: Exit(True);
      T_REG: Exit( reg.Equals(other.reg,state)) ;
      T_IMM: Exit( imm.Equals(other.imm,state));
      T_MEM: Exit( mem.Equals(other.mem,state)) ;
    end;
end;

function TOperand.ToString: string;

  function MemSizeName(size: Integer): string;
    begin
         case size of
           1:  Result := 'byte ptr';
           2:  Result := 'word ptr';
           4:  Result := 'dword ptr';
           6:  Result := 'fword';
           8:  Result := 'qword ptr';
           10: Result := 'tword';
           14: Result := 'm14';
           16: Result := 'xmmword';
           28: Result := 'm28';
           32: Result := 'yword';
           64: Result := 'zword';
         else
             Result := '';
         end;
    end;

begin
    case  Tipo of
     T_REG: Result := reg.ToString;
     T_IMM: Result := imm.ToString;
     T_MEM: Result := MemSizeName(Size.Value) + ' '+mem.ToString;
    else
        Result :=  '?';
    end;
end;

{ TIstruzione }

constructor TIstruzione.Create(mnem: Mnemonics; op1, op2, op3, op4: TOperand);
begin
    ZeroMemory(@Self, SizeOf(TIstruzione));
    Self.Create(mnem,4);
    operands[0] := op1;
    operands[1] := op2;
    operands[2] := op3;
    operands[3] := op4;
end;

constructor TIstruzione.Create(mnem: Mnemonics; op1, op2, op3: TOperand);
begin
    ZeroMemory(@Self, SizeOf(TIstruzione));
    Self.Create(mnem,3);
    operands[0] := op1;
    operands[1] := op2;
    operands[2] := op3;
end;

constructor TIstruzione.Create(mnem: Mnemonics; op1, op2: TOperand);
begin
    ZeroMemory(@Self, SizeOf(TIstruzione));
    Self.Create(mnem,2);
    operands[0] := op1;
    operands[1] := op2;
end;

constructor TIstruzione.Create(mnem: Mnemonics; op1: TOperand);
begin
    ZeroMemory(@Self, SizeOf(TIstruzione));
    Self.Create(mnem,1);
    operands[0] := op1;
end;

constructor TIstruzione.Create(mnem: Mnemonics; vOpCount: Integer);
begin
    ZeroMemory(@Self, SizeOf(TIstruzione));
    opcode  := TOpcode(mnem);
    opCount := vOpCount;
end;

class operator TIstruzione.Explicit( pCompare: TCompare<TIstruzione>): TIstruzione;
var
  c : TIstruzione;
begin
    c.compare := pCompare;
    c.opCount := 0;

    Result := c;
end;

function TIstruzione.FromCpuIstruzione(const insn: TCpuIstruz): TIstruzione;
var
  instr  : TIstruzione;
  op     : TCpuOperand;
  i      : Integer;

begin
    instr         := TIstruzione.Create(insn.opcode.mnem);
    instr.address := insn.address;
    instr.size    := insn.size;
    instr.eflags  := insn.eflags;

    for i := 0 to High(insn.regs_read) do
        instr.regs_read := instr.regs_read + [ TRegister( gConvert.convertReg(insn.regs_read[i])) ];

    for i := 0 to High(insn.regs_written) do
        instr.regs_written := instr.regs_written + [ TRegister(gConvert.convertReg(insn.regs_written[i])) ];

    for i := 0 to High(insn.groups)  do
        instr.groups := instr.groups + [ insn.groups[i] ];

    instr.refTo := insn.refTo;
    for i := 0 to High(insn.refFrom)  do
        instr.refFrom := instr.refFrom + [ insn.refFrom[i] ];

    CopyMemory(@instr.prefix, @insn.prefix, sizeof(insn.prefix));

    CopyMemory(@instr.bytes, @insn.bytes, SizeOf(insn.bytes));

    instr.opCount := insn.opCount;
    for i := 0 to insn.opCount - 1 do
    begin
        op := insn.operands[i];
        case op.tipo of
         T_REG:  instr.operands[i] := TOperand(TRegister(gConvert.convertReg(op.reg)));
         T_IMM:  instr.operands[i] := TOperand(TImmediate(op.imm.S));
         T_MEM: instr.operands[i]  := TOperand(TMemoria.Memoria(TSegment  (gConvert.convertSeg(op.mem.seg)),
                                                                TRegister (gConvert.convertReg(op.mem.base)),
                                                                TRegister (gConvert.convertReg(op.mem.index)),
                                                                TImmediate(op.mem.scale.S),
                                                                TImmediate(op.mem.disp.S)));
        end;
        instr.operands[i].size   := TImmediate(op.size.S);
        instr.operands[i].access := op.access;
    end;
    {$IFDEF DEBUG}instr.Istr_Str := instr.ToString; {$ENDIF}
    Result := instr;
end;

function TIstruzione.isMemoryRead:Boolean;
var
  i : Integer;
begin
    Result := False;
    for i := 0 to opCount - 1 do
       if operands[i].isMemoryRead then
         Exit(True);
end;

function TIstruzione.isMemoryWrite:Boolean;
var
  i : Integer;
begin
    Result := False;
    for i := 0 to opCount - 1 do
       if operands[i].isMemoryWrite then
         Exit(True);
end;

function TIstruzione.Equals(var other: TIstruzione; var state: TStato): Boolean;
var
  i : Integer;

begin
     if Assigned(compare)       then  Exit( compare(Self,other,state));
     if Assigned(other.compare) then  Exit( other.compare(other,Self,state));

     if not opcode.Equals(other.opcode, state) then Exit(False);

     if opCount <> other.opCount then  Exit(False);

     for i := 0 to opCount - 1 do
        if not operands[i].Equals(other.operands[i], state) then
             Exit(False);

     Result := True;
end;

function TIstruzione.GetOperand(Index: Integer): TOperand;
begin
    if Index > High(operands) then Exit;

    Result := operands[Index];

end;

function TIstruzione.LoadFromJson(const instrJO: TSuperArray; var sStato: TStato; var aMnem  : TMultiOp; lRepl : Boolean = False): TArray<TIstruzione>;
var
  i,j     : Integer;
  iJO     : ISuperObject;
  istruz  : TIstruzione;
  aOperand: TArray<TOperand>;
  operand : TOperand;
  mnem    : Mnemonics;
  sMnem   : TStringDynArray;
begin
    SetLength(Result,0);
    for i := 0 to instrJO.Length - 1 do
    begin
        iJO := instrJO.O[i];
        ZeroMemory( @istruz, SizeOf(TIstruzione));

        mnem := gconvert.str2ins( iJO.S['OpCode'] );

        if lRepl then  aOperand := operand.LoadReplFromJson(iJO.A['Operand'],sStato)
        else           aOperand := operand.LoadFromJson(iJO.A['Operand'],sStato) ;
        // carica tuttgli operandi e crea istruzione
        case Length(aOperand) of
           0: istruz.Create(mnem);
           1: istruz.Create(mnem,aOperand[0]);
           2: istruz.Create(mnem,aOperand[0],aOperand[1]);
           3: istruz.Create(mnem,aOperand[0],aOperand[1],aOperand[2]);
           4: istruz.Create(mnem,aOperand[0],aOperand[1],aOperand[2],aOperand[3]);
        end;
        // size
        istruz.size := iJO.I['Size'];
        // caso multi opcode
        if mnem = 0 then
        begin
            if lRepl = False then
            begin
                iJO :=  iJO.O['OpCode'];

                sMnem := SplitString(iJO.S['OpCodes'],';');
                aMnem.nOp := iJO.I['oP'];
                for j := 0 to High(sMnem) do
                   aMnem.OpCodes := aMnem.OpCodes + [ gconvert.str2ins(sMnem[j]) ] ;
            end else
            begin
                // per aggirare il problema di non avere ancora i dati reali da sostituire
                istruz.opcode.mnem := iJO.I['OpCode']
            end;
        end;

        Result := Result + [istruz];
    end;
end;

procedure TIstruzione.SetOperand(Index: Integer; const Value: TOperand);
begin
    if Index > High(operands) then Exit;

    operands[Index] := Value;
end;

function TIstruzione.ToString(PrintAddr: Boolean= False): string;
var
  str : string;
  i   : Integer;
begin
    str := '';
    if      prefix[0] = Ord(X86_PREFIX_LOCK) then str := 'lock '
    else if prefix[0] = Ord(X86_PREFIX_REP)  then str := 'rep '
    else if prefix[0] = Ord(X86_PREFIX_REPE) then str := 'repe '
    else if prefix[0] = Ord(X86_PREFIX_REPNE)then str := 'repne ';

    str := str + opcode.ToString;

    if opCount > 0 then
        str := str + ' ';
    for i := 0 to opCount - 1 do
    begin
        if i <> 0 then
        begin
            str := str + ',';
            str := str + ' ';
        end;
        str := str + operands[i].ToString;
    end ;
    if PrintAddr then Result := '0x'+ string(fIntToHex(address)) +': '+ str
    else              Result := str;
end;

end.
