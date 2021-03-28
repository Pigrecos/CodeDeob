unit Deobfuscator;

interface
     uses System.Classes, Winapi.Windows, System.SysUtils,
          PeepHole,Constant_Fold,DeadCode,ACTypes, AhoCorasick.Interval_int,
          System.Generics.Collections,Collections.LinkedList,
          Capstone,
          uAnalysis;

type

  TDeobFuscate = class;
  TCFGRevoverComplete = Reference to procedure(CFGRecovered : TLinkedList<TCpuIstruz>);

  TCFGRecover = class
   Private
      Ffunction  : TCFG_Analysis;
      FDisAsm    : TCapstone;

      procedure   OutDbg(dbgMsg: String);
      procedure   UpdateBB(BBStart: UInt64; var Lista: TLinkedList<TCpuIstruz>);
      function    FindAddr(VA: UInt64; Lista: TLinkedList<TCpuIstruz>; var Curr :TLinkedListNode<TCpuIstruz>): Boolean;

   public
      constructor Create(fFun : TCFG_Analysis= nil);
      destructor  Destroy; override;
      function    RecoverCFG: Boolean;
      function    OptimizeAllBB(vDeob : TDeobFuscate; ForceDeadCode: Boolean): Boolean;

      property funz   : TCFG_Analysis read Ffunction;

  end;


  TDeobFuscate = class
    private
      FIniCodeLen : UInt64;
      FFinCodeLen : UInt64;
      FIniBBLen   : UInt64;
      FFinBBLen   : UInt64;
      FNumOP      : UInt64;
      FInputFile  : string;
      FPathAsmFile: string;

      FSaveAsmFile: Boolean;
      FUsaDeadC_Sp: Boolean;
      FUsaOttimiz : Boolean;
      FIsVmEntry  : Boolean;

      FFun        : TCFG_Analysis;
      Fcfg        : TCFGRecover;
      FDisAsm     : TCapstone;
      FOnRecover  : TCFGRevoverComplete;

      FModo     : Byte ;
      FPeepHole : TPeepHole;
      FConstFold: TConstFold;
      FDeadCode : TDeadCode;
      FCFGRecov : TLinkedList<TCpuIstruz>;

      function VMRegFixer(var block: TArray<TIstruzione>): Boolean;
      function VMRegFixerBase(const block: TArray<TIstruzione>;  var Res: TArray<TIstruzione>;SearchDispl: Boolean = False): Boolean;
      function VMRegFixerIndex(const block: TArray<TIstruzione>;   var Res: TArray<TIstruzione>): Boolean;
      function isMemInsn(ins: TIstruzione): Boolean;
      function ComponiMem(mem: TMemoria; size: byte): string;
      function InternalOptimize(var vIn: TArray<TIstruzione>): Boolean;
      procedure MakeRef(var List: TLinkedList<TCpuIstruz>);

    public
      constructor Create(Arch: Byte = CP_MODE_32;InFile: string = '';JSonPath: string = '');
      destructor  Destroy; override;

      procedure DeobfuscateList(var vIn: TArray<TIstruzione>); overload;
      procedure DeobfuscateList(var lstIn: TLinkedList<TCpuIstruz>); overload;
      function  DeobfuscateAT(VAAddr: UInt64; OutList: TLinkedList<TCpuIstruz> = nil): string;
      procedure DoRecoverComplete;

      property  Modo        : Byte            read FModo        write FModo;
      property  InputFile   : string          read FInputFile   write FInputFile;
      property  PathAsmFile : string          read FPathAsmFile write FPathAsmFile;
      property  lSaveAsmFile: Boolean         read FSaveAsmFile write FSaveAsmFile;
      property  UsaDeadC_Sp : Boolean         read FUsaDeadC_Sp write FUsaDeadC_Sp ;
      property  UsaOttimiz  : Boolean         read FUsaOttimiz  write FUsaOttimiz;
      property  IsVmEntry   : Boolean         read FIsVmEntry;
      property  PeepHole    : TPeepHole       read FPeepHole ;
      property  ConstFold   : TConstFold      read FConstFold ;
      property  DeadCode    : TDeadCode       read FDeadCode ;
      property  DisAsm      : TCapstone       read FDisAsm;
      //
      property  OnCompleteRecover : TCFGRevoverComplete read FOnRecover  write FOnRecover;

      property IniCodeLen   : UInt64          read FIniCodeLen ;
      property FinCodeLen   : UInt64          read FFinCodeLen;
      property IniBBLen     : UInt64          read FIniBBLen;
      property FinBBLen     : UInt64          read FFinBBLen;
      property NumOP        : UInt64          read FNumOP;
  end;

  procedure print_disassembly(list:  TLinkedList<TCpuIstruz>;var outlst: TStringList; Show_Addr : Boolean = False );

  {$IFDEF TESTING}var dbgString :  TStringList; {$ENDIF}

implementation
        uses CapstoneX86,Assemble,Convert;

procedure print_disassembly(list:  TLinkedList<TCpuIstruz>;var outlst: TStringList; Show_Addr : Boolean = False );
var
 current  : TLinkedListNode<TCpuIstruz>;
 Istruz   : TCpuIstruz;

begin
    if list = nil then Exit;

    current :=  list.First;
    if current = nil then Exit;

    while current <> nil do
    begin
        Istruz := current.Data;
        if Show_Addr then
           //outlst.Add( Format('%x', [Istruz.address]) )
           outlst.Add( Format('%x: %s', [Istruz.address, Istruz.ToString ]) )
        else
           outlst.Add( Format('%s', [Istruz.ToString]) ) ;


        current := current.Next;
    end;
end;

{ TCFGRecover }

constructor TCFGRecover.Create(fFun : TCFG_Analysis= nil);
begin
    Ffunction  := fFun;
end;

destructor TCFGRecover.Destroy;
begin
    FDisAsm.Free;

end;

procedure TCFGRecover.OutDbg(dbgMsg: String);
begin
   {$IFDEF TESTING}
   OutputDebugString(PChar(dbgMsg));
   {$ENDIF}
end;

function TCFGRecover.FindAddr(VA: UInt64;Lista: TLinkedList<TCpuIstruz>; var Curr : TLinkedListNode<TCpuIstruz>): Boolean;
var
 n       : UInt64;
 Current: TLinkedListNode<TCpuIstruz>;
begin
    Result := False;

    Current := Lista.First;
    while Current <> nil do
    begin
         n := Current.Data.address;

         if n = VA then
         begin
             Curr := Current;
             Exit(True);
         end;
         Current := Current.Next;
    end;
end;

procedure TCFGRecover.UpdateBB(BBStart: UInt64; var Lista: TLinkedList<TCpuIstruz>);
var
  x      : UInt64;
  i      : Integer;
  Current: TLinkedListNode<TCpuIstruz>;
  cfIns  : TCfGIns;
  uFirst : UInt64;
begin
    i      := 0;
    uFirst := 0;
    repeat
         x := Ffunction.basic_blocks[BBStart][i].Insn.address;

         if not FindAddr(x,Lista,Current) then
         begin
             // cancellare per ultimo altrimenti rimangono bb incompleti
             if (BBStart = x) then
             begin
                 uFirst := x;
                 inc(i);
                 Continue;
             end;

             Ffunction.RemoveInstruction(x,BBStart) ;
             if not Ffunction.basic_blocks.ContainsKey(BBStart) then
                   OutDbg('hEAD BB  not eXIST');

             Continue;
         end else
         begin
           cfIns.OriginEA := Current.Data.address;
           cfIns.Insn     := Current.Data;
           Ffunction.basic_blocks[BBStart][i]  := cfIns;
         end;

        Inc(i);
    until i > Length(Ffunction.basic_blocks[BBStart]) - 1;

    if uFirst <> 0  then
       Ffunction.RemoveInstruction(uFirst,BBStart) ;

end;

function TCFGRecover.OptimizeAllBB(vDeob : TDeobFuscate; ForceDeadCode: Boolean): Boolean;
var
  modified   : Boolean;
  bb_ea      : UInt64;
  lstBB      : TLinkedList<TCpuIstruz>;
  OldLen,
  NewLen     : Integer;
begin
    modified := False;

    lstBB   := TLinkedList<TCpuIstruz>.Create;
    Ffunction.InitDFSFalseTraverse;

    while True do
    begin
        bb_ea := Ffunction.DFSFalseTraverseBlocks;

        if bb_ea = UInt64(-1) then Break;

        lstBB.Clear;
        Ffunction.ToList( bb_ea, lstBB);

        OldLen := lstBB.Count;

        vDeob.UsaDeadC_Sp := ForceDeadCode;
        vDeob.DeobfuscateList(lstBB);

        NewLen := lstBB.Count;

        if not modified then
           modified := OldLen <> NewLen;
        // syncronize
        UpdateBB(bb_ea,lstBB) ;

        Ffunction.UpdateAddTodo(bb_ea);
    end;
    Result := modified;

end;

function TCFGRecover.RecoverCFG: Boolean;
var
  modified, changed : Boolean;
  bb_ea,parent      : UInt64;
  instr             : TCfGIns;
  refs_from,refs_to : TList<TRef>;
  tblMark           : TDictionary<UInt64,UInt64>;
  item              : TPair<UInt64,UInt64>;
  lChkMark          : Boolean;

begin
    if Ffunction = nil then
      raise Exception.Create('Reduce Init Error');

    FDisAsm := Ffunction.DisAsm;
    tblMark := TDictionary<UInt64,UInt64>.Create;

    try
      modified := False ;
      changed  := True ;
      parent   := 0;
      while changed do
      begin
          bb_ea    := 0;
          lChkMark := False;
          tblMark.Clear;
          changed  := False;
          Ffunction.InitDFSFalseTraverse;
          while True do
          begin

              if bb_ea <> 0 then
                Ffunction.UpdateAddTodo(bb_ea);

              bb_ea := Ffunction.DFSFalseTraverseBlocks;
              if bb_ea = UInt64(-1) then Break;

              // si può eliminare(invece di lasciarlo come per i loop) se il jmp è riferito al blocco successivo
              if lChkMark then
              begin
                   lChkMark := False;
                   if not tblMark.ContainsValue(bb_ea) then
                        tblMark.Remove(instr.OriginEA);
              end;

              instr := Ffunction.GetBBLastInstruction(bb_ea);

              if FDisAsm.IsJmp(instr.Insn) then
              begin
                  OutDbg( Format('>ReduceJMP:Reduce1 - JMP@[%08x] BB[%08x] Disas[%s]',[instr.OriginEA,bb_ea,FDisAsm.Insn.ToString]));

                  refs_from := Ffunction.GetRefsFrom(instr.OriginEA);

                  if instr.OriginEA = Ffunction.start_ea then
                  begin
                      //if a function starts with a jump and has no refs pointing to it just skip it
                      try
                          if Ffunction.GetRefsTo(instr.OriginEA).Count > 1 then
                              continue
                      except
                          Ffunction.start_ea := refs_from[0].Keys.ToArray[0];
                      end;
                  end
                  else if (refs_from.Count  = 0) or (refs_from[0].Keys.ToArray[0] = 0) or (refs_from.Count > 1) then
                      continue     //this is a case for jmp reg
                  else if Ffunction.GetRefsTo(instr.OriginEA).Count > 1 then
                      continue    //this is a case of switch jump
                  else if Ffunction.GetRefsTo(instr.OriginEA).Count = 1 then
                  begin
                      parent := Ffunction.GetRefsTo(instr.OriginEA)[0].Keys.ToArray[0];
                      if Ffunction.GetRefsFrom(parent).Count > 1 then
                      begin
                          // si può eliminare(invece di lasciarlo come per i loop) se il jmp è riferito al blocco successivo
                          if Ffunction.GetRefsTo( refs_from[0].Keys.ToArray[0]).Count <> 1 then
                          begin
                               lChkMark  := True;
                               if not tblMark.ContainsKey(instr.OriginEA) then
                                  tblMark.Add( instr.OriginEA,refs_from[0].Keys.ToArray[0])  ;
                               continue
                          end;
                      end;

                  end;
                  refs_to := Ffunction.GetRefsTo(refs_from[0].Keys.ToArray[0]);

                  if (refs_to.Count = 1) and (refs_from[0].Keys.ToArray[0] <> Ffunction.start_ea) then
                  begin
                      //Update CFG; remove jmp instruction, update references, merge BB's and update BB table
                      Ffunction.RemoveInstruction(instr.OriginEA, bb_ea) ;
                      changed  := True;
                      modified := True ;
                  end
                  else if (refs_to.Count > 1) and (refs_from[0].Keys.ToArray[0] <> Ffunction.start_ea) then
                  begin  // si può eliminare(invece di lasciarlo come per i loop) se il jmp è riferito al blocco successivo
                       lChkMark  := True;
                       if not tblMark.ContainsKey(instr.OriginEA) then
                          tblMark.Add( instr.OriginEA,refs_from[0].Keys.ToArray[0])  ;
                  end;
              end
              else if not FDisAsm.IsCFI(instr.Insn) then
              begin
                  refs_from := Ffunction.GetRefsFrom(instr.OriginEA);

                  if refs_from.Count <> 1 then
                  begin    //assert rule
                      OutDbg( Format('@ %08x',[instr.OriginEA]));
                      raise Exception.Create('Reduce :Riferimenti errati');
                  end;

                  if Ffunction.GetRefsTo(instr.OriginEA).Count > 1 then
                      continue  //this is a case of switch jump
                  else if Ffunction.GetRefsTo(instr.OriginEA).Count = 1 then
                      parent := Ffunction.GetRefsTo(instr.OriginEA)[0].Keys.ToArray[0];
                      if Ffunction.GetRefsFrom(parent).Count > 1 then
                          continue ;

                  refs_to := Ffunction.GetRefsTo(refs_from[0].Keys.ToArray[0]);

                  if (refs_to.Count = 1) and (refs_from[0].Keys.ToArray[0] <> Ffunction.start_ea) then
                  begin
                     //Ffunction.basic_blocks[bb_ea].AddRange( Ffunction.basic_blocks[ refs_from[0].Keys.ToArray[0] ].ToArray )  ;
                      Ffunction.basic_blocks[bb_ea] := Ffunction.basic_blocks[bb_ea] + Ffunction.basic_blocks[ refs_from[0].Keys.ToArray[0] ] ;
                      Ffunction.basic_blocks.Remove( refs_from[0].Keys.ToArray[0] ) ;

                      changed  := True;
                      modified := True;
                  end;
              end;
              // DFSFalseTraverseBlock Update Ref
              //Ffunction.UpdateAddTodo(bb_ea);
          end;
          // elimina i salti con due riferimenti di cui alla 1# istruz. del blocco successivo
          if ( Length(Ffunction.addr_todo) > 0) then  // non ultimo blocco ultima istruzione
          begin
              for item in tblMark do
              begin
                   if (Ffunction.RemoveInstruction(item.Key)) then
                   begin
                       changed  := True;
                       modified := True;
                   end;
                   tblMark.Remove(item.Key);
              end;
          end;
      end;
    finally
      tblMark.Free;
    end;
    Result := modified;
end;

{ TDeobFuscate }

procedure DebugMsg(const Msg: String);
begin
   {$IFDEF TESTING}OutputDebugString(PChar(Msg)){$ENDIF}
end;

constructor TDeobFuscate.Create(Arch: Byte = CP_MODE_32;InFile: string = '';JSonPath: string = '');
begin
    if      Arch = 4 then Arch := CP_MODE_32
    else if Arch = 8 then Arch := CP_MODE_64;

    FModo       := Arch;
    FInputFile  := InFile;

    FModo       := Modo;

    FOnRecover  := nil;
    FPathAsmFile:= '';
    FSaveAsmFile:= True;
    FUsaDeadC_Sp:= False;
    FUsaOttimiz := True;
    FIsVmEntry  := False;

    FDisAsm  := TCapstone.Create;
    FDisAsm.Open;
    if FileExists(FInputFile) then
    begin
        FDisAsm.NomeFile := AnsiString(FInputFile);
        if      FDisAsm.Mode = 4 then FModo := CP_MODE_32
        else if FDisAsm.Mode = 8 then FModo := CP_MODE_64
    end;

    FFun  := TCFG_Analysis.Create(True,FDisAsm);
    Fcfg  := TCFGRecover.Create(FFun);

    FPeepHole      := TPeepHole.Create(JSonPath);
    FPeepHole.Modo := FModo;

    FConstFold := TConstFold.Create(FModo);
    FDeadCode  := TDeadCode.Create(FModo);

end;

destructor TDeobFuscate.Destroy;
begin
     FDisAsm.Free;
     FFun.Free;
     Fcfg.Free;
     inherited;
end;

procedure TDeobFuscate.DoRecoverComplete;
begin
    if Assigned(FOnRecover) then
      FOnRecover(FCFGRecov);
end;

function TDeobFuscate.isMemInsn(ins: TIstruzione): Boolean;
begin
    Result :=  (ins.isMemoryRead) or (ins.isMemoryWrite)
end;

function TDeobFuscate.ComponiMem(mem: TMemoria; size: byte): string;
var
  size_indicator : string;
  base, index    : string;
  disp,scale     : string;
begin
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

function TDeobFuscate.VMRegFixerBase(const block: TArray<TIstruzione>; var Res: TArray<TIstruzione>;SearchDispl: Boolean = False): Boolean;
var
  index, b,a,
  prev_index: Integer;
  insn,prev,
  newIStruz : TIstruzione;
  op,op1,op2: TOperand;
  base,
  index_,
  reg_found : TRegisters;
  reg       : TRegister;
  scale,
  disp,
  imm_found : Int64;
  size      : Byte;
  found,
  FlagDispl : Boolean;
  mnem      : string;
  mem       : TMemoria;
  nLimit    : Word;
  notDelete : Boolean;
begin
    Result   := False;

    index := High(block);
    a     := -1;
    b     := -1;

    if      FModo = CP_MODE_32 then nLimit := $FF
    else if FModo = CP_MODE_64 then nLimit := $FFFF ;

    while index >= 0 do
    begin
        insn := block[index];

        if (insn.address = $51116E)  or (insn.address = $511175) then
        insn := insn;

        notDelete := False;
        // Check if it is a memory instruction
        if isMemInsn(insn) then
        begin
            DebugMsg('VMRegFixerBase Istruzione Proc.: '+insn.ToString);
            for op in insn.operands do
            begin
                if op.Tipo = T_MEM then
                begin
                    base   := op.mem.base.reg;
                    index_ := op.mem.index.reg;
                    scale  := op.mem.scale.Value;
                    disp   := op.mem.disp.Value;
                    size   := op.Size.Value;

                    // Check if it uses only the BASE
                    if (base <> REG_INVALID) and (index_ = REG_INVALID) and (scale = 1) and (disp = 0) then
                    begin
                        // Search a MOV base, REG and a ADD base, IMM instructions
                        reg_found := REG_INVALID;
                        imm_found := $CCCC;

                        prev_index := index - 1;
                        while (prev_index >= 0) and ( (imm_found = $CCCC) or (reg_found = REG_INVALID) ) do
                        begin
                            prev := block[prev_index];

                            DebugMsg('VMRegFixerBase Ricerca Base-Displ: '+prev.ToString);

                            // Check if it is: MOV base, REG or ADD base, IMM
                            found := False;
                            if prev.opCount = 2 then
                            begin
                                op1 := prev.operands[0];
                                op2 := prev.operands[1];

                                if (op1.Tipo = T_REG) and (op1.reg.reg = base) then
                                begin
                                    if (prev.opcode.mnem = Mnemonics(X86_INS_ADD)) and (op2.Tipo = T_IMM) and (imm_found = $CCCC) then
                                    begin
                                        if (SearchDispl) and  (op2.imm.Value >= nLimit) then
                                        begin
                                            prev_index := 0 ;
                                            Continue;
                                        end;
                                        imm_found := op2.imm.Value;
                                        found     := True ;
                                        a         := prev_index;
                                    end
                                    else if (prev.opcode.mnem = Mnemonics(X86_INS_MOV)) and (op2.Tipo = T_REG) and (reg_found = REG_INVALID) then
                                    begin
                                        reg_found := op2.reg.reg;
                                        found     := True;
                                        b         := prev_index;
                                    end;
                                end;
                             end;

                             var bck_prev_index : integer := 0;
                             // caso lettura registro memoria interrompere
                             if (op1.Tipo = T_MEM) and ((op1.mem.base.GetParent = TRegister(base).GetParent) or (op1.mem.index.GetParent = TRegister(base).GetParent)) then
                             begin
                                 bck_prev_index := prev_index;
                                 prev_index := 0
                             end
                             else if ((op2.Tipo = T_MEM) and ((op2.mem.base.GetParent = TRegister(base).GetParent) or (op2.mem.index.GetParent = TRegister(base).GetParent))) then
                             begin
                                 bck_prev_index := prev_index;
                                 prev_index := 0
                             end;

                             (* -- Verifica per eliminare questo caso di errore
                               51116E: mov dword ptr [r11], 0x7C7C7DAF
                               511175: sub dword ptr [r11], eax

                               51116E: mov dword ptr [rbp+0x80], 0x7C7C7DAF
                               511175: sub dword ptr [r11], 0x7C7C7DAF
                               *)
                             if prev_index = 0 then
                             begin
                                 if (op1.mem.base.reg <> REG_INVALID) and (op1.mem.index.reg = REG_INVALID) and (op1.mem.scale.Value = 1) and (op1.mem.disp.Value = 0) and (op1.mem.base.reg = base ) then
                                     prev_index := bck_prev_index
                                 else if (op2.mem.base.reg <> REG_INVALID) and (op2.mem.index.reg = REG_INVALID) and (op2.mem.scale.Value = 1) and (op2.mem.disp.Value = 0) and (op2.mem.base.reg = base ) then
                                     prev_index := bck_prev_index;

                                 if prev_index<> 0 then
                                   notDelete := True;
                             end;


                            // verifica se la base viene sovrascitta la 'base'
                            if found = False then
                            begin
                                for reg in prev.regs_written do
                                begin
                                    if reg.GetParent = TRegister(base).GetParent then
                                        prev_index := 0 ;
                                end;
                            end;
                             // verifica se il registro trovato non venga riscritto
                            if (found = False) and (reg_found <>  REG_INVALID ) then
                            begin
                                for reg in prev.regs_written do
                                begin
                                    if reg.GetParent = TRegister(reg_found).GetParent then
                                        prev_index := 0 ;
                                end;
                            end;
                            ZeroMemory(@op1,SizeOf(TOperand));
                            ZeroMemory(@op2,SizeOf(TOperand));

                            prev_index := prev_index - 1;
                        end;

                        if SearchDispl then FlagDispl := reg_found = REG_INVALID
                        else                FlagDispl := reg_found <> REG_INVALID;

                        // Update Istruzione e cancellazione istruzioni interessate
                        if (FlagDispl) and (imm_found <> $CCCC) and (insn.opCount = 2) then
                        begin
                            mnem := insn.opcode.ToString;
                            op1  := insn.operands[0];
                            op2  := insn.operands[1];

                            if SearchDispl  then mem.base  := TRegister(base)
                            else                 mem.base  := TRegister(reg_found) ;

                            mem.index := TRegister(index_);
                            mem.scale := TImmediate(scale);
                            mem.disp  := TImmediate(imm_found);

                            if op1.Tipo = T_MEM then
                            begin
                                if op2.Tipo = T_REG then
                                   newIStruz := ACAssemble(AnsiString(mnem + ' ' + ComponiMem(mem, size) + ', ' + op2.reg.ToString), insn, FModo )
                                else if op2.Tipo = T_IMM then
                                   newIStruz := ACAssemble(AnsiString(mnem + ' ' + ComponiMem(mem, size) + ', ' + op2.imm.ToString), insn, FModo )
                            end
                            else if op2.Tipo = T_MEM then
                            begin
                                if op1.Tipo = T_REG then
                                    newIStruz := ACAssemble(AnsiString(mnem + ' ' + op1.reg.ToString + ', ' + ComponiMem(mem, size)), insn, FModo )
                            end;
                            // Cancella vecchia instruzione ed inserisce la nuova
                            Delete(Res,index,1);
                            Insert(newIStruz,res,index);

                            if notDelete  = False then
                            begin
                                DebugMsg('VMRegFixerBase Deleting Istr 1: '+Res[a].ToString);
                                DeleteRef(Res,a,FModo);
                                Delete(Res,a,1);
                            end;
                            // cancella solo se previsto
                            if SearchDispl = False then
                            begin
                                if notDelete  = False then
                                begin
                                    DebugMsg('VMRegFixerBase Deleting Istr 1: '+Res[b].ToString);
                                    DeleteRef(Res,b,FModo);
                                    Delete(Res,b,1);
                                end;
                            end;

                            Result := True
                        end;
                    end;
                    break
                end;
            end;
        end;
        index := index - 1;
    end;
end;

function TDeobFuscate.VMRegFixerIndex(const block: TArray<TIstruzione>; var Res: TArray<TIstruzione>): Boolean;
var
  index, a,
  prev_index: Integer;
  insn,prev,
  newIstruz : TIstruzione;
  op,op1,op2 : ACTypes.TOperand;
  base,
  index_     : TRegisters;
  reg        : TRegister;
  scale,
  disp,
  imm_found  : Int64;
  size       : Byte;
  found      : Boolean;
  mnem       : string;
  mem        : TMemoria;
  nLimit     : Cardinal;
  NotDelDispl: Boolean;
begin
    Result := False;

    index := High(block);
    nLimit:= $FF;
    a     := -1;

    if      FModo = CP_MODE_32 then nLimit := $FF
    else if FModo = CP_MODE_64 then nLimit := $FFFF ;


    while index >= 0 do
    begin
        insn := block[index];

        // Check if it is a memory instruction
        if isMemInsn(insn) then
        begin
            DebugMsg('VMRegFixerIndex Istruzione Proc.: '+insn.ToString);
            NotDelDispl := False;
            for op in insn.operands do
            begin
                if op.Tipo = T_MEM then
                begin
                    base   := op.mem.base.reg;
                    index_ := op.mem.index.reg;
                    scale  := op.mem.scale.Value;
                    disp   := op.mem.disp.Value;
                    size   := op.Size.Value;

                    // Check if it uses BASE and INDEX

                    if (base <> REG_INVALID) and (index_ <> REG_INVALID) and (scale = 1) and (disp = 0) then
                    begin
                        // Search a MOV index_, IMM
                        imm_found := $CCCC;

                        prev_index := index - 1;
                        while (prev_index >= 0) and  (imm_found = $CCCC)  do
                        begin
                            prev := block[prev_index];

                            DebugMsg('VMRegFixerIndex Ricerca Index : '+prev.ToString);

                            // Check if it is: MOV index_, IMM
                            found := False;
                            if prev.opCount = 2 then
                            begin
                                op1 := prev.operands[0];
                                op2 := prev.operands[1];

                                if (prev.opcode.mnem = Mnemonics(X86_INS_MOV)) and (op1.Tipo = T_REG) and (op1.reg.GetParent = TRegister(index_).GetParent) then
                                begin
                                    if  (op2.Tipo = T_IMM) and (imm_found = $CCCC) then
                                    begin
                                        if UInt64(op2.imm.Value) < nLimit then
                                        begin
                                            imm_found := op2.imm.Value;
                                            found     := True ;
                                            a := prev_index;
                                        end;
                                    end
                                end
                                // caso + di una istruzione usa stesso displ. non cancellare displ
                                 {mov ebx, 0x9D
                                  mov dword ptr [ebp+ebx], 0x7B3FD5BF
                                  xor dword ptr [ebp+ebx], 0x7B7FD5BF}
                                else if ((op1.Tipo = T_MEM) and (op1.mem.index.reg = index_)) or ((op2.Tipo = T_MEM) and (op2.mem.index.reg = index_)) then
                                       NotDelDispl := True; ;
                            end;
                            // Check if this instruction overwrites 'base'
                            if found = False then
                            begin
                                for reg in prev.regs_written do
                                begin
                                    if reg.GetParent = TRegister(index_).GetParent then
                                        prev_index := 0 ;
                                end;
                            end;

                            prev_index := prev_index - 1;
                        end;

                        // Update Istruzione
                        if (imm_found <> $CCCC) and (insn.opCount = 2) then
                        begin
                            mnem := insn.opcode.ToString;
                            op1  := insn.operands[0];
                            op2  := insn.operands[1];

                            mem.base  := TRegister(base);
                            mem.index := TRegister(REG_INVALID);
                            mem.scale := TImmediate(scale);
                            mem.disp  := TImmediate(imm_found);

                            if op1.Tipo = T_MEM then
                            begin
                                if op2.Tipo = T_REG then
                                   newIstruz := ACAssemble(AnsiString(mnem + ' ' + ComponiMem(mem, size) + ', ' + op2.reg.ToString), insn,FModo )
                                else if op2.Tipo = T_IMM then
                                   newIstruz := ACAssemble(AnsiString(mnem + ' ' + ComponiMem(mem, size) + ', ' + op2.imm.ToString), insn,FModo )
                            end
                            else if op2.Tipo = T_MEM then
                            begin
                                if op1.Tipo = T_REG then
                                    newIstruz := ACAssemble(AnsiString(mnem + ' ' + op1.reg.ToString + ', ' + ComponiMem(mem, size)), insn,FModo )
                            end;
                            Delete(Res,index,1);
                            Insert(newIstruz,res,index);

                            if NotDelDispl = False then
                            begin
                                DebugMsg('VMRegFixerIndex Deleting Istr 1: '+Res[a].ToString);
                                DeleteRef(Res,a,FModo);
                                Delete(Res,a,1);
                            end;

                            Result := True
                        end;
                    end;
                    break
                end;
            end;
        end;
        index := index - 1;
    end;
end;

function TDeobFuscate.VMRegFixer(var block: TArray<TIstruzione>): Boolean;
var
  simplified : Boolean;
begin
    Result := False;

    simplified := VMRegFixerBase(block, block);
    if simplified then Result := True;

    simplified := VMRegFixerIndex(block, block);
    if simplified then Result := True;

    simplified := VMRegFixerBase(block, block,True);
    if simplified then Result := True;

end;

function TDeobFuscate.InternalOptimize(var vIn: TArray<TIstruzione>): Boolean;
var
  simplified,
  global_simplified : Boolean;
  LEmits            : TList<TEmit>;
  lenCode           : Integer;

  {$IFDEF TESTING}
  procedure PrintTest;
  var
    i : Integer;
  begin
      dbgString.Clear;
      for i := 0 to High(vIn) do
         dbgString.Add(vin[i].ToString(True)) ;

      dbgString.SaveToFile('TESTING.TXT');
  end;
  {$ENDIF}
begin
    {$IFDEF TESTING}
    if Assigned(dbgString) then dbgString.Clear
    else   dbgString := TStringList.Create;
    {$ENDIF}
    global_simplified := False;

    {$IFDEF TESTING}
    PrintTest;
    {$ENDIF}

    // Apply pattern matching
    simplified := True;
    while simplified do
    begin
        lenCode := Length(vIn);
        simplified := FPeepHole.ApplyPeepHole(vIn,vIn,LEmits);
        if (simplified) and (lenCode =  Length(vIn)) then
            simplified := False;

        if simplified then global_simplified := True;
        {$IFDEF TESTING}
        PrintTest;
        {$ENDIF}
    end;

    simplified := FConstFold.constantFolding(vIn,True) ;
    if simplified then global_simplified := True;

    {$IFDEF TESTING}
    PrintTest;
    {$ENDIF}

    // Apply DeadCode Elimination
    simplified := FDeadCode.DeadCode(vIn) ;
    if simplified then global_simplified := True;

    {$IFDEF TESTING}
    PrintTest;
    {$ENDIF}

    if global_simplified = False then
    begin
       simplified := FConstFold.constantFolding(vIn) ;
       if simplified then global_simplified := True
    end;

    {$IFDEF TESTING}
    PrintTest;
    {$ENDIF}

    if global_simplified = False then
    begin
       simplified := VMRegFixer(vIn) ;
       if simplified then global_simplified := True;
    end;

    {$IFDEF TESTING}
    PrintTest;
    {$ENDIF}

    if (FUsaDeadC_Sp) and (global_simplified = False) then
    begin
        simplified := FDeadCode.DeadCodeMem(vIn, vIn);
        if simplified then global_simplified := True;
    end;


    Result :=  global_simplified;

end;

procedure TDeobFuscate.MakeRef(var List: TLinkedList<TCpuIstruz>);
var
 j        : Integer;
 found    : Boolean;
 RefToIstr,
 RefFromIstr : PCpuIstruz;
 NodeRefTo,
 NodeRefFrom: TLinkedListNode<TCpuIstruz>;

begin
    if List.Count < 1 then   Exit;

    j := 0;
    NodeRefTo := List.First;

    while NodeRefTo <> nil do
    begin
        RefToIstr := @NodeRefTo.Data;
        if FDisAsm.IsCFI(NodeRefTo.Data) and (NodeRefTo.Data.operands[0].imm.u <> 0)then
        begin
               found := False;
               RefToIstr^.refTo := NodeRefTo.Data.operands[0].imm.u;

               NodeRefFrom := List.First;
               while NodeRefFrom <> nil do
               begin
                    RefFromIstr := @NodeRefFrom.Data;
                    if  NodeRefTo.Data.refTo = NodeRefFrom.Data.address then
                    begin
                        found := True;
                        SetLength(RefFromIstr^.refFrom,Length(RefFromIstr^.refFrom)+1);
                        RefFromIstr^.refFrom[High(RefFromIstr^.refFrom)].RefFrom := NodeRefTo.Data.address;
                        RefFromIstr^.refFrom[High(RefFromIstr^.refFrom)].idxRefTo:= j;
                    end;

                    NodeRefFrom := NodeRefFrom.Next;
               end;
               if found = False then RefToIstr.refTo := 0;
        end;

        inc(j);
        NodeRefTo := NodeRefTo.Next;
    end;
end;

procedure TDeobFuscate.DeobfuscateList(var lstIn: TLinkedList<TCpuIstruz>);
var
  Istr      : TLinkedListNode<TCpuIstruz>;
  vIn       : TArray<TIstruzione> ;
  tmpIstruz : TIstruzione;
  tmpCpuIstr: TCpuIstruz;
  i         : Integer;
begin

    Istr := lstIn.First;
    SetLength(vIn,0);
    while Istr <> nil do
    begin
        tmpIstruz := tmpIstruz.FromCpuIstruzione(Istr.Data);
        vIn := vIn + [ tmpIstruz ];

        Istr := Istr.Next;
    end;

    DeobfuscateList(vIn);

    lstIn.Clear;
    for i  := 0 to High(vIn) do
    begin
        tmpCpuIstr := ACAssembleCpuI(AnsiString(vIn[i].ToString), vIn[i], FModo);
        lstIn.AddLast(tmpCpuIstr);
    end;

end;

procedure TDeobFuscate.DeobfuscateList(var vIn: TArray<TIstruzione>);
var
  simplified : Boolean;
begin
    simplified := True;

    while simplified do
      simplified := InternalOptimize(vIn)
end;

function TDeobFuscate.DeobfuscateAT(VAAddr: UInt64; OutList: TLinkedList<TCpuIstruz>): string;
var
   current      : TLinkedListNode<TCpuIstruz> ;
   startAddr    : UInt64;
   modified     : Boolean;
   FAsmList     : TStringList;

begin

      if FPathAsmFile <> '' then Result := FPathAsmFile+'\Proc_'+ IntToHex(VAAddr,8)+'.asm'
      else                       Result := 'Proc_'+ IntToHex(VAAddr,8)+'.asm';

      FModo  := FDisAsm.Mode ;

      if       FModo = 4 then FModo := CP_MODE_32
      else if  FModo = 8 then FModo := CP_MODE_64;

      FCFGRecov := TLinkedList<TCpuIstruz>.Create;

      try
          startAddr := VAAddr;

          FFun.Init(VAAddr);
          Fcfg.funz.startAnalysis(startAddr);
          FIniCodeLen := Fcfg.funz.CountLine;
          FIniBBLen   := Fcfg.funz.NumBB;
          FNumOP      := Fcfg.funz.NumOP;

          FAsmList := TStringList.Create;

          {$IFDEF TESTING_DEOB}
          //Fcfg.funz.ToList(Fcfg.funz.ListaIstr);

          print_disassembly(Fcfg.funz.ListaIstr,FAsmList, true);

          FAsmList.Insert(0,';'+FInputFile);
          FAsmList.Insert(1,'');
          FAsmList.Insert(1,'');

          if FModo = CP_MODE_32 then FAsmList.Insert(3,';<'+IntToHex(VAAddr,8)+'>')
          else                       FAsmList.Insert(3,';<'+IntToHex(VAAddr,16)+'>');
          FAsmList.Insert(4,'');
          if FModo = CP_MODE_32 then  FAsmList.Insert(5,'Bits 32'+#13#10#13#10)
          else                        FAsmList.Insert(5,'Bits 64'+#13#10#13#10);

          FAsmList.SaveToFile( {FPathAsmFile+}'asm\Proc_TESTING_DEOB_'+ IntToHex(VAAddr,8)+'.asm');
          {$ENDIF}

          modified := True;
          while modified do
          begin
              modified := False;

              modified := modified or Fcfg.RecoverCFG;
          end;
          Fcfg.funz.AssertCFGStructure;

          FFinBBLen   := Fcfg.funz.basic_blocks.Count;

          {$IFDEF TESTING}
          Fcfg.funz.PrintDebugInfo;
          {$ENDIF}

          // basic block to lista istruzione
          Fcfg.funz.ToList(FCFGRecov);
          DoRecoverComplete;

          (* ottimizza il codice se abilitata l'ottimizzazione*)
          if FUsaOttimiz then
          begin
               (* crea tutti i riferimenti  *)
               MakeRef(FCFGRecov) ;
               DeobfuscateList(FCFGRecov);
          end;

          FFinCodeLen := FCFGRecov.Count;

          if FSaveAsmFile then
          begin
              FAsmList.Clear;

              print_disassembly(FCFGRecov,FAsmList,True);

              FAsmList.Insert(0,';'+FInputFile);
              FAsmList.Insert(1,'');
              FAsmList.Insert(1,'');

              if FModo = CP_MODE_32 then FAsmList.Insert(3,';<'+IntToHex(VAAddr,8)+'>')
              else                       FAsmList.Insert(3,';<'+IntToHex(VAAddr,16)+'>');
              FAsmList.Insert(4,'');
              if FModo = CP_MODE_32 then  FAsmList.Insert(5,'Bits 32'+#13#10#13#10)
              else                        FAsmList.Insert(5,'Bits 64'+#13#10#13#10);

              FAsmList.SaveToFile(Result);
          end;

      finally
          if not FSaveAsmFile then Result := '';

          if OutList <> nil then
          begin
               OutList.Clear;
               current := FCFGRecov.First;
               while current <> nil do
               begin
                   if current.Data.opcode.mnem = Ord(X86_INS_CMPXCHG) then
                     FIsVmEntry := True;

                   OutList.AddLast(current.Data);
                   current := current.Next;
               end;
          end;
          FCFGRecov.Free;
      end;

end;

end.
