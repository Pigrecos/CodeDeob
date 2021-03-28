unit ACStato;

interface
   uses System.SysUtils, System.Generics.Collections,System.TypInfo,ACTypes;

type

  TStateValue<T> = class
    private
      FSet    : Boolean;
      FVal    : T;

      function  GetVal: T;
      procedure SetVal(const Value: T);
    public
      constructor Create();
      function    Equals(const other: T; var state: TStato):   Boolean; virtual;

      property tVal : T       read GetVal write SetVal;
      property tSet : Boolean read FSet ;
  end;

  TStateValue_Operand = class(TStateValue<TOperand>)
    public
     function    Equals(const other: TOperand; var state: TStato): Boolean;override;
  end;
  TStateValue_Register = class(TStateValue<TRegister>)
    public
     function    Equals(const other: TRegister; var state: TStato): Boolean;override;
  end;
  TStateValue_Immediate = class(TStateValue<TImmediate>)
    public
     function    Equals(const other: TImmediate; var state: TStato): Boolean;override;
  end;
  TStateValue_Memoria = class(TStateValue<TMemoria>)
    public
     function    Equals(const other: TMemoria; var state: TStato): Boolean;override;
  end;
  TStateValue_OpCode = class(TStateValue<TOpCode>)
    public
     function    Equals(const other: TOpCode; var state: TStato): Boolean;override;
  end;

  TStatoHelper = record helper for TStato
   const
     MaxStateCount = 5;
   class var
     operands  : Array[0..MaxStateCount - 1] of TStateValue_Operand ;
     registers : Array[0..MaxStateCount - 1] of TStateValue_Register  ;
     values    : Array[0..MaxStateCount - 1] of TStateValue<TImmediate> ;
     memorys   : Array[0..MaxStateCount - 1] of TStateValue_Memoria ;
     opcodes   : Array[0..MaxStateCount - 1] of TStateValue_OpCode ;

   public
     procedure Clear;
     function SegWild       (index: Integer)    : TCompare<TSegment>;
     function RegWild       (index: Integer)    : TCompare<TRegister>;
     function ValWild       (index: Integer)    : TCompare<TImmediate>;
     function MakeOperandN  (index: Integer)    : TCompare<TOperand>;
     function MakeRegisterN (index: Integer)    : TCompare<TRegister>;
     function MakeRegisterSize(bitsize: Integer): TCompare<TRegister>;
     function MakeMemoryN   (index: Integer)    : TCompare<TMemoria>;
     function MakeValueN    (index: Integer)    : TCompare<TImmediate>;
     function MakeOpcodeN   (index: Integer)    : TCompare<TOpcode> ;
     function MakeOpcodeList(opIndex: Integer; possible: TArray<Mnemonics>) : TCompare<TOpcode>;
  end;

implementation
      uses Capstone;
{ TStatoHelper }

procedure TStatoHelper.Clear;
var
  i  : Integer;
  o  : TStateValue_Operand;
  r  : TStateValue_Register;
  imm: TStateValue_Immediate;
  m  : TStateValue_Memoria;
  op : TStateValue_OpCode;
begin
    for i := 0 to MaxStateCount - 1 do
    begin
        if Assigned(operands[i])  then  operands[i].Free  ;
        if Assigned(registers[i]) then  registers[i].Free ;
        if Assigned(values[i])    then  values[i].Free    ;
        if Assigned(memorys[i])   then  memorys[i].Free   ;
        if Assigned(opcodes[i])   then  opcodes[i].Free   ;
    end ;

    for i := 0 to MaxStateCount - 1 do
    begin
        o   := TStateValue_Operand.Create;
        r   := TStateValue_Register.Create;
        imm := TStateValue_Immediate.Create;
        m   := TStateValue_Memoria.Create;
        op  := TStateValue_OpCode.Create;

        operands[i]  := o;
        registers[i] := r;
        values[i]    := imm;
        memorys[i]   := m;
        opcodes[i]   := op;
    end
end;

function TStatoHelper.SegWild(index: Integer): TCompare<TSegment>;
begin
    Result  := Function (const a,b: TSegment; var state : TStato): Boolean
    begin
         Result := True;
    end ;
end;

function  TStatoHelper.RegWild(index: Integer): TCompare<TRegister>;
begin
    Result  := function (const a,b: TRegister; var state : TStato): Boolean
    begin
         Result := True;
    end ;
end;

function  TStatoHelper.ValWild(index: Integer): TCompare<TImmediate>;
begin
    Result  := Function (const a,b: TImmediate; var state : TStato): Boolean
    begin
         Result := True;
    end ;
end;

function TStatoHelper.MakeMemoryN(index: Integer): TCompare<TMemoria>;
begin
    Result := function (const a,b: TMemoria; var state : TStato): Boolean
    begin
        if state.memorys[index].FSet then //already matched before
             Exit( state.memorys[index].Equals(b, state) );
        state.memorys[index].tVal := b;
        Result := true;
    end;
end;

function TStatoHelper.MakeOpcodeList(opIndex: Integer;  possible: TArray<Mnemonics>): TCompare<TOpcode>;
var
  mnem : Mnemonics;

begin
    Result := function (const a,b: TOpcode; var state : TStato): Boolean
    var
      i    : Integer;
    begin
        Result := False;

        if state.registers[0] = nil then state.Clear;

        if not state.opcodes[opIndex].FSet then
        begin
            for i := 0 to High(possible) do
            begin
                mnem := possible[i];
                if mnem = b.mnem then
                begin
                    state.opcodes[opIndex].tVal := b;
                    Exit(true);
                end;
            end;
        end else
            Result := true;
    end;
end;

function TStatoHelper.MakeOpcodeN(index: Integer): TCompare<TOpcode>;
begin
    Result := function (const a,b: TOpcode; var state : TStato): Boolean
    begin
        if state.registers[0] = nil then state.Clear;

        if state.opcodes[index].FSet then
             Exit( state.opcodes[index].Equals(b, state) );
        state.opcodes[index].tVal := b;
        Result := true;
    end;
end;

function TStatoHelper.MakeOperandN(index: Integer): TCompare<TOperand>;
begin
    Result := function (const a,b: TOperand; var state : TStato): Boolean
    begin
        if state.registers[0] = nil then state.Clear;

        if state.operands[index].FSet then
             Exit( state.operands[index].Equals(b, state) );
        state.operands[index].tVal := b;
        Result := true;
    end;
end;

function TStatoHelper.MakeRegisterN(index: Integer): TCompare<TRegister>;
var
  j     : Integer;
  value : TRegister;
begin
    Result := function (const a,b: TRegister; var state : TStato): Boolean
    begin
        if state.registers[0] = nil then state.Clear;

        if state.registers[index].FSet then
             Exit( state.registers[index].Equals(b, state) );

        value.reg := REG_INVALID;
        j     := 0;
        // evita che registri uguali vengano implementati come differenti)
        while j <= High(state.registers) do
        begin
            if state.registers[j].FSet then
            begin
                if state.registers[j].tVal.reg  = b.reg then
                begin
                     state.registers[index].tVal := value;
                     Exit(False);
                end;
            end;
            inc(j);
        end;
        state.registers[index].tVal := b;
        Result := true;
    end;
end;

function TStatoHelper.MakeRegisterSize(bitsize: Integer): TCompare<TRegister>;
begin
    Result := function (const a,b: TRegister; var state : TStato): Boolean
    begin
        Result := b.Size * 8 = bitsize;
    end;
end;

function TStatoHelper.MakeValueN(index: Integer): TCompare<TImmediate>;
begin
    Result := function (const a,b: TImmediate; var state : TStato): Boolean
    begin
        if state.registers[0] = nil then state.Clear;

        if state.values[index].FSet then
             Exit( state.values[index].Equals(b, state) );
        state.values[index].tVal := b;
        Result := true;
    end;
end;

{ TStateValue<T> }

constructor TStateValue<T>.Create;
begin
    FSet := False;
end;

function TStateValue<T>.Equals(const other: T; var state: TStato): Boolean;
begin

end;

function TStateValue<T>.GetVal: T;
begin
    Result := FVal;
end;

procedure TStateValue<T>.SetVal(const Value: T);
begin
    FSet := True;
    FVal := Value;
end;

{ TStateValue_OpCode }

function TStateValue_OpCode.Equals(const other: TOpCode; var state: TStato): Boolean;
begin
   Result := FVal.Equals(other, state);
end;

{ TStateValue_Operand }

function TStateValue_Operand.Equals(const other: TOperand; var state: TStato): Boolean;
begin
    Result := FVal.Equals(other, state);
end;

{ TStateValue_Register }

function TStateValue_Register.Equals(const other: TRegister; var state: TStato): Boolean;
begin
    Result := FVal.Equals(other, state);
end;

{ TStateValue_Immediate }

function TStateValue_Immediate.Equals(const other: TImmediate; var state: TStato): Boolean;
begin
    Result := FVal.Equals(other, state);
end;

{ TStateValue_Memoria }

function TStateValue_Memoria.Equals(const other: TMemoria; var state: TStato): Boolean;
begin

    Result := FVal.Equals(other, state);
end;

end.
