unit ACPattern;

interface
   uses System.SysUtils, Winapi.Windows,ACTypes,ACStato, Assemble,System.Generics.Collections,Capstone,CapstoneX86;

type

  TPattern = record
   private
       state      : TStato;
   public
       priority : Integer;
       flag     : Integer;
       Nome     : string;
       instrs   : TArray<TIstruzione>;
       replsIns : TArray<TIstruzione>;

       function  Produce(var vOut: TArray<TIstruzione>; var vIn: TArray<TIstruzione>; indice: Integer;Modo: Byte): Boolean;
       function  Search(const data : TArray<TIstruzione>; start : size_t = 0): Int64;
       function  Match(var data : TArray<TIstruzione>; const start : size_t ): Boolean;
       procedure Add(const instr : TIstruzione);overload ;
       procedure Add(const instr : AnsiString; mode : Integer = CP_MODE_32; addr : UInt64 = 0); overload;
       procedure Clear;

  end;

implementation

{ Pattern }



function TPattern.Produce(var vOut: TArray<TIstruzione>; var vIn: TArray<TIstruzione>; indice: Integer;Modo: Byte): Boolean;
var
  Istruz   : TIstruzione ;
  i,j      : Integer;
  fixSize  : Byte;
  imm      : TImmediate;

begin
    Result := False;

    for i := 0 to High(replsIns) do
    begin
        Istruz := replsIns[i];
        // caso multi opcode
        if Istruz.opcode.mnem <= 3 then
           Istruz.opcode := state.opcodes[ Istruz.opcode.mnem ].tVal;

        var bckIstruz := Istruz;

        for j := 0 to Istruz.opCount - 1 do
        begin
            case Istruz.operands[j].Tipo of
               T_REG: begin
                          if (Integer(Istruz.operands[j].reg.reg) <= state.MaxStateCount - 1 ) and (state.registers[Integer(Istruz.operands[j].reg.reg)].tSet) then
                             Istruz.operands[j].reg := state.registers[Integer(Istruz.operands[j].reg.reg)].tVal;
                      end;
               T_IMM: begin
                          if (Istruz.operands[j].imm.Value <= state.MaxStateCount - 1) and (state.values[Istruz.operands[j].imm.Value].tSet) then
                             Istruz.operands[j].imm := state.values[Istruz.operands[j].imm.Value].tVal;
                          if flag = $11  then  (*fp00000032*)
                          begin
                              imm := state.values[1].tVal;
                              imm.Value := imm.Value - state.values[2].tVal.Value;
                              state.values[1].tVal := imm ;
                              Istruz.operands[j].imm := imm;
                          end;
                      end;
               T_MEM: begin
                         if (Integer(Istruz.operands[j].mem.base.reg) <= state.MaxStateCount - 1 ) and (state.memorys[Integer(Istruz.operands[j].mem.base.reg)].tSet) then
                             Istruz.operands[j].mem := state.memorys[Integer(Istruz.operands[j].mem.base.reg)].tVal
                         // per i casi in cui base e index sono sconosciuti fino alla comparazione
                         else if (Integer(Istruz.operands[j].mem.base.reg) <= state.MaxStateCount - 1 )  and (Integer(Istruz.operands[j].mem.base.reg) > 0 ) then
                         begin
                             if (state.registers[Integer(Istruz.operands[j].mem.base.reg)].tSet) then
                              Istruz.operands[j].mem.base := state.registers[Integer(Istruz.operands[j].mem.base.reg)].tVal
                         end ;
                         if (Integer(Istruz.operands[j].mem.index.reg) <= state.MaxStateCount - 1 )  and (Integer(Istruz.operands[j].mem.index.reg) > 0 ) then
                         begin
                             if (state.registers[Integer(Istruz.operands[j].mem.index.reg)].tSet) then
                              Istruz.operands[j].mem.index := state.registers[Integer(Istruz.operands[j].mem.index.reg)].tVal
                         end ;
                         if (Integer(Istruz.operands[j].mem.disp.Value) <= state.MaxStateCount - 1 )  and (Integer(Istruz.operands[j].mem.disp.Value) > 0 ) then
                         begin
                             if (state.values[Integer(Istruz.operands[j].mem.disp.Value)].tSet) then
                              Istruz.operands[j].mem.disp := state.values[Integer(Istruz.operands[j].mem.disp.Value)].tVal
                         end
                      end;
           T_OPERAND: Istruz.operands[j] := state.operands[Integer(Istruz.operands[j].reg.reg)].tVal;
            end;
            if Istruz.operands[j].Size.Value < 0 then
            begin
                 fixSize := StrToInt64('$'+inttostr(Abs(Istruz.operands[j].Size.Value)));
                 Istruz.operands[j].Size.Value := vIn[indice + ( ((fixSize and $F0)shr 4) - 1)].operands[(fixSize and $0F)-1].Size.Value;
                 if (Istruz.size = $FF) and ((Istruz.operands[j].mem.base.reg = ESP) or (Istruz.operands[j].mem.base.reg = RSP))  then
                 begin
                     if      Istruz.operands[j].Size.Value = 2 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 2
                     else if Istruz.operands[j].Size.Value = 4 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 4
                     else if Istruz.operands[j].Size.Value = 8 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 8
                 end;
            end
            else if (Istruz.size = $FF) and ((Istruz.operands[j].mem.base.reg = ESP) or (Istruz.operands[j].mem.base.reg = RSP))  then
            begin
                if      Istruz.operands[j].Size.Value = 2 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 2
                else if Istruz.operands[j].Size.Value = 4 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 4
                else if Istruz.operands[j].Size.Value = 8 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 8
            end
            else if (Istruz.size = $100) and ((Istruz.operands[j].mem.base.reg = ESP) or (Istruz.operands[j].mem.base.reg = RSP))  then
            begin  { --fp00000011-- }
                fixSize := vIn[indice].operands[0].Size.Value;
                if      fixSize = 2 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 2
                else if fixSize = 4 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 4
                else if fixSize = 8 then  Istruz.operands[j].mem.disp.Value := Istruz.operands[j].mem.disp.Value - 8
            end
            else if Int16(Istruz.Size) < 0 then
            begin
                 // parte alta del registro
                 if Abs(Int16(Istruz.Size)) =  $32 then
                 begin
                     if Istruz.operands[j].Tipo = T_REG then
                        Istruz.operands[j].reg.reg := Istruz.operands[j].reg.GetReg(Istruz.operands[j].reg.GetParent, $20);
                 end else
                 begin
                     fixSize := StrToInt('$'+inttostr(Abs(Int16(Istruz.Size))));
                     Istruz.operands[j].Size.Value := vIn[indice + ( ((fixSize and $F0)shr 4) - 1)].operands[(fixSize and $0F)-1].Size.Value;
                     if Istruz.operands[j].Tipo = T_REG then
                     begin
                          if Istruz.operands[j].reg.GetReg(Istruz.operands[j].reg.GetParent, Istruz.operands[j].Size.Value) <> REG_INVALID then
                            Istruz.operands[j].reg.reg := Istruz.operands[j].reg.GetReg(Istruz.operands[j].reg.GetParent, Istruz.operands[j].Size.Value);
                     end;
                 end;
            end;
        end;


        if (Istruz.opcode.mnem = Mnemonics(X86_INS_POP)) and (Istruz.operands[0].reg.Size = 1) then
        begin
            var sizeValue := vIn[indice+1].operands[1].imm.Value;

            if ( vIn[indice+1].opcode.mnem = Mnemonics(X86_INS_ADD) ) and (vIn[indice+1].operands[1].tipo = T_Imm) then
                Istruz.operands[0].reg.reg := Istruz.operands[0].reg.GetReg(Istruz.operands[0].reg.GetParent,sizeValue);
        end;

        Istruz := ACAssemble(AnsiString(Istruz.ToString),vIn[ indice+i ],Modo);

        vOut := vOut + [Istruz];
        Result := True;
    end;

end;

procedure TPattern.Add(const instr: TIstruzione);
begin
    instrs := instrs + [instr];
end;

procedure TPattern.Add(const instr: AnsiString; mode: Integer; addr: UInt64);
var
  tmpI : TIstruzione;
begin
    tmpI := TIstruzione.Create(Ord(X86_INS_NOP));
    tmpI.address := addr;

    instrs := instrs + [ACAssemble(instr, tmpI,mode)];
end;

procedure TPattern.Clear;
begin
       priority := 0;
       Flag     := 0;
       Nome     := '';
       SetLength(instrs,0);
       SetLength(replsIns,0);
end;

function TPattern.Match(var data: TArray<TIstruzione>; const start: size_t): Boolean;
var
 i,vPos,idx : Integer;
 SubRegI,
 SubRegO,
 RegI,RegO  : Byte;
 tmpOp      : TOperand;

 function IsRealEspDisp: Boolean;
 var
   j : Integer;
 begin
      Result := True;
      // verifica necessaria per evitere errori in [esp + disp]
      if instrs[vPos].Size = 255 then
      begin
          for j := 0 to data[i].opCount -1 do
          begin
              if data[i].operands[j].Tipo = T_MEM then
              begin
                  if (data[i].operands[j].mem.base.reg = ESP) or (data[i].operands[j].mem.base.reg = RSP)  then
                    if data[i].operands[j].mem.disp.Value < 2 then
                      Exit(False);
              end;

          end;
      end;
 end;

begin
    state.Clear;

    if Length(instrs) > Length(data) then   Exit(False);

    idx  := 0;
    vPos := 0;
    i    := start;
    if i = - 1 then
      i := 0;
    while i < Length(data)  do
    begin
        if not IsRealEspDisp then Exit(False);

        if data[i].Equals(instrs[vPos], state) then
        begin
            Inc(vPos);
            if vPos = Length(instrs) then
            begin
                if flag = $64 then (* -- fp00000031 --*)
                begin
                    if ( (data[start+1].operands[0].mem.base.reg = ESP) or (data[start+1].operands[0].mem.base.reg = RSP) ) and
                       (data[start+1].operands[0].mem.disp.Value <= 0)  then
                       Exit(False)
                end;
                if flag = $70 then (* -- fp00000026 --*)
                begin
                    if ( (data[start].operands[0].reg.reg = ESP) and (data[start].operands[1].imm.Value = 4) ) or
                       ( (data[start].operands[0].reg.reg = RSP) and (data[start].operands[1].imm.Value = 8) ) then
                       Exit(False)
                end;
                if flag = $90 then // evita due arg di tipo mem(push mem; pop mem es. mov mem, mem
                begin
                    if (data[start].operands[0].Tipo = T_MEM) and (data[start+1].operands[0].Tipo = T_MEM)  then
                       Exit(False)
                end;
                if flag = $11 then // evita due reg diversi (*fp00000032*)
                begin
                    if (data[start].operands[0].reg.GetParent) <> (data[start+1].operands[0].reg.GetParent)  then
                       Exit(False)
                end;
                if priority >= 300 then (* -- evita di eliminare istruzioni con riferimenti(in casi particolari) --*)
                begin
                    if Length(data[start+1].refFrom) > 0  then
                       Exit(False)
                end;
                Exit(True);
            end;
            // -- fp00000019 -- aggiunto gestione confronto con subreg
            if ((flag and $800000) = $800000) and ((idx+1) = ( (flag shr $10)and $0F)) then  (* -- fp00000016 --*)
            begin
                SubRegI:= (flag shr $0C)and $0F;
                SubRegO:= (flag shr $08)and $0F;
                RegI   := (flag shr $04)and $0F;
                RegO   := (flag )and $0F;

                if (data[start+(SubRegI-1)].operands[SubRegO-1].reg.GetParent = data[start+(RegI-1)].operands[RegO-1].reg.GetParent) and
                   (data[start+(SubRegI-1)].operands[SubRegO-1].reg.Size = 4) and (data[start+(RegI-1)].operands[RegO-1].reg.Size = 8) then
                begin
                    // se il subReg è sulla prima istruz. si deve modificare altrimenti
                    // i confronti suulle altre istr. del patterns possono fallire
                    if SubRegI = 1 then
                    begin
                       tmpOp                   := state.operands[1].tVal;
                       state.registers[1].tVal := data[start+(RegI-1)].operands[RegO-1].reg;
                       tmpOp.reg               := data[start+(RegI-1)].operands[RegO-1].reg;
                       state.operands[1].tVal  := tmpOp;
                    end;
                end;
            end ;
        end
        { # push  rcx
          # mov   ecx, 0    2
          # sub   rcx, rax
          # xchg  rax/ rcx
          # pop   rcx
          -------------- oppure
          # mov r11d, 0x66DBCC6A   1
          # add r11, rax
          # sub r11, 0x66DBCC6A
          --------------oppure
          # mov  ecx, 0x1234     1
          # add  r12, rcx}
        else if ((flag and $800000) = $800000) and ((idx+1) = ( (flag shr $10)and $0F)) then  (* -- fp00000016 --*)
        begin
            SubRegI:= (flag shr $0C)and $0F;
            SubRegO:= (flag shr $08)and $0F;
            RegI   := (flag shr $04)and $0F;
            RegO   := (flag )and $0F;

            if (data[start+(SubRegI-1)].operands[SubRegO-1].reg.GetParent = data[start+(RegI-1)].operands[RegO-1].reg.GetParent) and
               (data[start+(SubRegI-1)].operands[SubRegO-1].reg.Size = 4) and (data[start+(RegI-1)].operands[RegO-1].reg.Size = 8) then
            begin
                Inc(vPos);
                if vPos = Length(instrs) then
                   Exit(True);
            end;
        end else
        begin
            Break;
        end;

        inc(i);
        inc(idx);
    end;
    Result :=  False;

end;

function TPattern.Search(const data: TArray<TIstruzione>; start: size_t): Int64;
var
 i,vPos : Integer;
begin
    state.Clear;

    if Length(instrs) > Length(data) then   Exit(-1);

    vPos := 0;
    i    := 0;
    while i < Length(data)  do
    begin
        if data[i].Equals(instrs[vPos], state) then
        begin
            Inc(vPos);
            if vPos = Length(instrs) then
                Exit(i - Length(instrs) + 1);
        end else
        begin
            i   := i - vPos;
            vPos := 0;
            state.Clear;
        end;

        inc(i);
    end;
    Result :=  -1;
end;

end.
