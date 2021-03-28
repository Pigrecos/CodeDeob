unit uAnalysis;


interface
   uses
      Winapi.Windows, System.SysUtils,System.Generics.Collections, System.Generics.Defaults,System.Classes,
      Collections.LinkedList,
      Capstone,CapstoneApi,CapstoneX86,
      Assemble,
      Emulation;
type
  CFNode = record
           parentGraph  : UInt64; //function of which this node is a part
           start        : UInt64; //start of the block
           Fine         : UInt64; //end of the block (inclusive)
           brtrue       : UInt64; //destination if condition is true
           brfalse      : UInt64; //destination if condition is false
           icount       : UInt64; //number of instructions in node
           terminal     : Boolean;//node is a RET

           constructor Create(uParentG,uStart,uFine: UInt64);
       end;

   PCfGIns = ^TCfGIns;
   TCfGIns = record
     OriginEA : UInt64;
     Insn     : TCpuIstruz;
   end;
   TIns     = TArray<TCfGIns>;
   TRef     = TDictionary<UInt64,Boolean>;

   TCFG_Analysis = class
     private
       FCountLine        : UInt64;
       FNumBB            : UInt64;
       FNumOP            : UInt64;
       FDisAsm           : TCapstone;
       FListaIstr        : TLinkedList<TCpuIstruz>;
       FEmulator         : TEmulation;

       Fstart_ea         : UInt64;
       FreplaceRingNot3  : Boolean;
       FEmulateCall      : UInt64;

       Faddr_done        : TDictionary<UInt64,UInt64>; // done blocks; key=ea, value=bb addr that ea belongs to
       Faddr_todo        : TArray<UInt64>;             // blocks todo
       Faddr_appended_len: Word;

       Ffunction_calls   : TArray<UInt64>;            //#address of call and destination
       FConsumeCall      : TArray<UInt64>;
       Ffake_ret         : TArray<UInt64>;            //#list of addresses of fake RET opcodes
       FFakeJJTable      : TRef;
       FFakeCallX64Safe  : TArray<UInt64>;            // lista delle call +05 utilizzata per risolvere il problema in x64 push imm64

       //bb graph edges
       Frefs_to          : TDictionary<UInt64,TRef> ;
       Frefs_from        : TDictionary<UInt64,TRef> ;
       FFastRefTo        : TDictionary< UInt64,Tarray<UInt64> > ;  // Per migliorare prestazioni analisi
       FFastRefFrom      : TDictionary< UInt64,TArray<UInt64> > ;  // Per migliorare prestazioni analisi

       Fbasic_blocks     : TDictionary<UInt64,TIns>;   //#key: bb addr, value: [] of instructions
       Fcurrent_block    : UInt64 ;                    //#address of current block
       procedure    OutDbg(dbgMsg: String);
       procedure    AddRefsFrom(ref_from, ref_to: Uint64; flag : Boolean=False);
       procedure    AddRefsTo(ref_to, ref_from: UInt64; flag : Boolean=False);

       function     refs(ea: UInt64; isFrom, isFlow: Boolean): TArray<UInt64>;
       function     fillInstructionData(ea: UInt64): UInt64;
       procedure    DelRefs(ref_remove: UInt64);
       procedure    SplitBlock( split_addr: UInt64);
       function     DFSBBSearchHead(find_addr: UInt64): UInt64;
       function     CodeRefsFrom(ea: Uint64; flow: Boolean): TArray<UInt64>;
       function     CodeRefsTo(ea: Uint64; flow: Boolean): TArray<UInt64>;
       function     GetIstruzioneItem(Addr: UInt64; var Bb_Head: UInt64; var idx : Integer): TCfGIns;
       function     GetContextCode(VAAddr: UInt64; var ctxFakeJccT: TRef): TLinkedList<TCpuIstruz>;
       function     OpPredicate(ListaIstr: TLinkedList<TCpuIstruz>; jcc_Cmd: Word; var lEsegueSalto: Boolean): Boolean;
       procedure    Add_I(const istruz: TCpuIstruz; var list: TLinkedList<TCpuIstruz>;lDeleteLast: Boolean);
       function     IsStopCond(insn: TCpuIstruz): Boolean;

     public
       constructor Create(bReplaceRingNot3: Boolean = True;vDisAsm: TCapstone = nil);
       destructor  Destroy; override;
       procedure   Init(uStartEA: UInt64);
       function    GetRefsFrom(ea_from: UInt64): TList<TRef>;
       function    GetRefsTo(ea_to: UInt64): TList<TRef>;
       procedure   PrintDebugInfo(lPrintRef: Boolean = False;lPrintBBAddr: Boolean =False);

       procedure   startAnalysis(startEA: UInt64);
       procedure   AssertCFGStructure;
       function    DFSFalseTraverseBlocks: UInt64;
       procedure   UpdateAddTodo(ea: UInt64);
       procedure   InitDFSFalseTraverse;
       function    GetBBLastInstruction(ea: UInt64): TCfGIns;
       function    RemoveInstruction(ea:UInt64; bb_ea: UInt64 = 0): Boolean;
       procedure   ToList(BBStart: UInt64; var Lista: TLinkedList<TCpuIstruz>);  overload;
       procedure   ToList(var Lista: TLinkedList<TCpuIstruz>);  overload;

     property   start_ea: UInt64                               read Fstart_ea          write Fstart_ea;
     property   replaceRingNot3   : Boolean                    read FreplaceRingNot3   write FreplaceRingNot3;
     property   addr_done         : TDictionary<UInt64,UInt64> read Faddr_done         write Faddr_done;
     property   addr_todo         : TArray<UInt64>             read Faddr_todo         write Faddr_todo;
     property   addr_appended_len : Word                       read Faddr_appended_len write Faddr_appended_len;
     property   function_calls    : TArray<UInt64>             read Ffunction_calls    write Ffunction_calls;
     property   fake_ret          : TArray<UInt64>             read Ffake_ret          write Ffake_ret ;
     property   FakeCallX64Safe   : TArray<UInt64>             read FFakeCallX64Safe;
     //bb graph edges
     property   refs_to           : TDictionary<UInt64,TRef>   read Frefs_to           write Frefs_to;
     property   refs_from         : TDictionary<UInt64,TRef>   read Frefs_from         write Frefs_from;

     property   basic_blocks      : TDictionary<UInt64,TIns>   read Fbasic_blocks      write Fbasic_blocks;
     property   current_block     : UInt64                     read Fcurrent_block     write Fcurrent_block;

     property   DisAsm            : TCapstone                  read FDisAsm;
     property   ListaIstr         : TLinkedList<TCpuIstruz>    read FListaIstr;
     property   CountLine         : UInt64                     read FCountLine;
     property   NumBB             : UInt64                     read FNumBB;
     property   NumOP             : UInt64                     read FNumOP;
   end;

 {$INCLUDE Define.inc};

implementation
       

var
   __refs : TDictionary<UInt64,Boolean>;    //tmp ref for DSFFalseTraverseBlock

function FindArrayVal(InA: TArray<UInt64>; Value: UInt64; var Idx: Integer): Boolean;
var
  i      : Integer;
  Match  : Boolean;
begin
    Match := False;
    Idx   := 0;
    for i := Low(InA) to High(InA) do
    begin
        if InA[i] = Value then
        begin
            Match := True;
            Idx   := i;
            break;
        end;
    end;
    Result := Match;

end;

function Contains(const AArray: TArray<UInt64> ;const Value: UInt64 ): boolean;
var
  i: integer;
begin
    for i := Low(AArray) to High(AArray) do
      if Value = AArray[i]  then
        Exit(true);
    result := false;
end;

 { CFNode }
constructor CFNode.Create(uParentG,uStart,uFine: UInt64);
begin
         parentGraph :=  uParentG;
         start       :=  uStart;
         Fine        :=  uFine;
         brtrue      := 0;
         brfalse     := 0;
         icount      := 0;
         terminal    := False;
end;

constructor TCFG_Analysis.Create(bReplaceRingNot3: Boolean= True;vDisAsm: TCapstone = nil);

begin
    FreplaceRingNot3 := bReplaceRingNot3 ;

    Faddr_appended_len := 0;
    Fcurrent_block     := 0;

    Faddr_done        := TDictionary<UInt64,UInt64>.Create;
    SetLength(Faddr_todo,0);
    SetLength(Ffunction_calls,0);
    SetLength(Ffake_ret,0);

    //bb graph edges
    Frefs_to     := TDictionary<UInt64,TRef>.Create ;
    Frefs_from   := TDictionary<UInt64,TRef>.Create ;
    FFastRefTo   := TDictionary<UInt64,TArray<UInt64>>.Create;
    FFastRefFrom := TDictionary<UInt64,TArray<UInt64>>.Create;

    Fbasic_blocks:= TDictionary<UInt64,TIns>.Create;

    FDisAsm          := TCapstone.Create ;
    FDisAsm.Mode     := vDisAsm.Mode;
    FDisAsm.Open;
    if FileExists(vDisAsm.NomeFile) then
       FDisAsm.NomeFile := vDisAsm.NomeFile;

    FListaIstr   := TLinkedList<TCpuIstruz>.Create;

    FEmulator  := TEmulation.Create(FDisAsm.Mode);

    FFakeJJTable := TRef.Create;

    //tmp ref for DSFFalseTraverseBlock
    __refs := TDictionary<UInt64,Boolean>.Create;

end;

destructor TCFG_Analysis.Destroy;
begin
      Faddr_done.Free ;
      SetLength(Faddr_todo,0);
      SetLength(Ffunction_calls,0) ;
      SetLength(Ffake_ret,0);
      SetLength(FFakeCallX64Safe,0);

      //bb graph edges
      Frefs_to.Free;
      Frefs_from.Free;

      Fbasic_blocks.Free;

      FListaIstr.Free;
      FEmulator.Free;
      FFastRefTo.Free;
      FFastRefFrom.Free;
end;

procedure TCFG_Analysis.Init(uStartEA: UInt64);
begin
    Fstart_ea        := uStartEA;

    Faddr_appended_len := 0;
    Fcurrent_block     := 0;

    Faddr_done.Clear;
    SetLength(Faddr_todo,0);
    SetLength(Ffunction_calls,0);
    SetLength(Ffake_ret,0);
    SetLength(FFakeCallX64Safe,0);

    //bb graph edges
    Frefs_to.Clear; ;
    Frefs_from.Clear;
    FFastRefTo.Clear;
    FFastRefFrom.Clear;

    Fbasic_blocks.Clear;

    FListaIstr.Clear;

    FFakeJJTable.Clear;

    //tmp ref for DSFFalseTraverseBlock
    __refs.Clear;
end;

procedure TCFG_Analysis.ToList(var Lista: TLinkedList<TCpuIstruz>);
var
 i      : Integer;
 Istruz : TCpuIstruz;
 bb_ea  : UInt64;
begin
    Lista.Clear;

    InitDFSFalseTraverse;
    while True do
    begin
        bb_ea := DFSFalseTraverseBlocks;
        if bb_ea = UInt64(-1) then Break;

        for i := 0 to Length(Fbasic_blocks[bb_ea]) - 1 do
        begin
             Istruz := Fbasic_blocks[bb_ea][i].Insn;
             lista.AddLast(Istruz);
        end;

        UpdateAddTodo(bb_ea);
    end;
end;

procedure TCFG_Analysis.ToList(BBStart: UInt64; var Lista: TLinkedList<TCpuIstruz>);
var
i      : Integer;
Istruz : TCpuIstruz;
begin
   for i := 0 to Length(Fbasic_blocks[BBStart]) - 1 do
   begin
        Istruz := Fbasic_blocks[BBStart][i].Insn;
        lista.AddLast(Istruz);
   end;
end;

procedure TCFG_Analysis.OutDbg(dbgMsg: String);
begin
    {$IFDEF TESTING}
    OutputDebugString(PChar(dbgMsg));
    {$ENDIF}
end;

function TCFG_Analysis.refs(ea : UInt64; isFrom,isFlow: Boolean): TArray<UInt64>;
var
  lstTemp   : TArray<UInt64>;
  uTo,uFrom : UInt64;

begin
    lstTemp := [];

    if isFrom then
    begin
        FDisAsm.DisAssembleVA(ea);
        if (isFlow) and (FDisAsm.id <> ord( X86_INS_JMP)) and  (FDisAsm.id <> ord( X86_INS_RET)) then
          lstTemp := lstTemp + [ea + FDisAsm.size];

        if FFastRefFrom.ContainsKey(ea) then
           for uFrom in  FFastRefFrom[ea] do
             if not Contains(lstTemp,uFrom) then
               lstTemp := lstTemp + [ uFrom ];
    end else
    begin
        // se l'istruzione precedente non è un jmp
        uTo := FDisAsm.DisasmBack(ea,1);
        if (isFlow) and (FDisAsm.id <> ord( X86_INS_JMP)) and (FDisAsm.id <> ord( X86_INS_RET)) and (uTo <> 0) then
         if ea <> Fstart_ea then
            lstTemp := lstTemp + [uTo];

        if FFastRefTo.ContainsKey(ea) then
          for uTo in  FFastRefTo[ea] do
            if not Contains(lstTemp,uTo) then
              lstTemp := lstTemp + [uTo];
    end;
    Result := lstTemp;
end;

function TCFG_Analysis.CodeRefsTo(ea: Uint64; flow:Boolean): TArray<UInt64>;
begin
    Result := refs(ea, False,flow)
end;

function TCFG_Analysis.CodeRefsFrom(ea: Uint64; flow:Boolean): TArray<UInt64>;
begin
     Result := refs(ea, True,flow)
end;

procedure TCFG_Analysis.AddRefsTo(ref_to, ref_from : UInt64; flag : Boolean=False);
var
  dTmp : TRef;
begin
     if Frefs_to.ContainsKey(ref_to) then
     begin
         if not Frefs_to[ref_to].ContainsKey(ref_from) then
             Frefs_to[ref_to].Add(ref_from, flag)
     end
     else begin
          dTmp  := TDictionary<UInt64,Boolean>.Create;
          dTmp.Add(ref_from,flag);
          Frefs_to.Add(ref_to,dTmp);
     end;

end;

procedure TCFG_Analysis.AddRefsFrom(ref_from, ref_to : Uint64; flag : Boolean=False);
     (*
         Add reference that key points to val.
         Bool signifies if jcc reference is True or False branch.
         For normal graph traversal (top down); key -> (val1, ..., valN).
      *)
var
  dTmp : TRef;
begin
     if Frefs_from.ContainsKey(ref_from) then
     begin
         if not Frefs_from[ref_from].ContainsKey(ref_to) then
             Frefs_from[ref_from].Add(ref_to, flag)
     end
     else begin
          dTmp  := TDictionary<UInt64,Boolean>.Create;
          dTmp.Add(ref_to,flag);
          Frefs_from.Add(ref_from,dTmp)
     end;
end;

function TCFG_Analysis.GetRefsTo(ea_to: UInt64): TList<TRef>;
var
  ea    : TPair<UInt64,Boolean> ;
  tmpLst: TList<TRef>;
begin
     tmpLst := TList<TRef>.Create;

     if not Frefs_to.ContainsKey(ea_to) then  Exit(tmpLst) ;

     for ea in Frefs_to[ea_to] do
         tmpLst.Add(Frefs_to[ea_to]) ;

     Result := tmpLst;
end;

function TCFG_Analysis.GetRefsFrom(ea_from:UInt64): TList<TRef>;
var
  ea    : TPair<UInt64,Boolean> ;
  tmpLst: TList<TRef>;
begin
     tmpLst := TList<TRef>.Create;

     if not Frefs_from.ContainsKey(ea_from) then  Exit(tmpLst) ;

     for ea in Frefs_from[ea_from] do
         tmpLst.Add(Frefs_from[ea_from]);

     Result := tmpLst;
end;

function TCFG_Analysis.GetBBLastInstruction(ea: UInt64):TCfGIns;
begin
    if not Fbasic_blocks.ContainsKey(ea) then
        raise Exception.Create('GetBBLastInstruction');

    Result := Fbasic_blocks[ea][ High(Fbasic_blocks[ea]) ];
end;

procedure TCFG_Analysis.PrintDebugInfo(lPrintRef: Boolean = False;lPrintBBAddr: Boolean =False);
var
  subRife : TPair<UInt64,Boolean>;
  s,s1    : string;
  list    : Tstringlist;
  LArray  : TArray<UInt64>;
  valueK,
  bb_ea   : UInt64;
  vIns    : TCfGIns;

  procedure prinBlock(Key: Uint64);
  var
     i : Integer;
  begin
      s  := Format('Key: %x (%d) n° Istruz.: %d',[Key,Key,Length(Fbasic_blocks[Key])]);

      list.Add(s);
      for i := 0 to Length(Fbasic_blocks[Key]) - 1 do
      begin
          vIns := Fbasic_blocks[Key][i];
          s := Format('-------OriginEA:%x  (%d)   :  %s  %s',[vIns.OriginEA,vIns.OriginEA,string(vIns.Insn.Opcode.ToString),string(vIns.Insn.ToString)]);
          list.Add(s);
      end;
  end;

begin
    list := TStringList.Create;

    s := '';
    s1:= '';

    if lPrintRef then
    begin
        list.Add('Frefs_to');

        LArray := Frefs_to.Keys.ToArray;
        TArray.Sort<UInt64>(LArray);
        for valueK in LArray do
        begin
            s  := 'Key: '+IntToStr(valueK)+ '( '+IntToHex(valueK,4)+ ' )';
            for subRife in Frefs_to[valueK] do
            begin
               s1 := ' ['+ IntToStr(subRife.Key)+ '( '+IntToHex(subRife.Key,4)+ ' )'+ ' : '+ BoolToStr(subRife.Value,True)+ ']';
               list.Add(s+s1);
            end;
        end;

        list.Add('');
        list.Add('Frefs_from');
        s := '';
        s1:= '';
        LArray := Frefs_from.Keys.ToArray;
        TArray.Sort<UInt64>(LArray);
        for valueK in LArray do
        begin
            s  := 'Key: '+IntToStr(valueK)+ '( '+IntToHex(valueK,4)+ ' )';
            for subRife in Frefs_from[valueK] do
            begin
                s1 := ' ['+ IntToStr(subRife.Key)+ '( '+IntToHex(subRife.Key,4)+ ' )'+' : '+ BoolToStr(subRife.Value,True)+ ']';
                list.Add(s+s1);
            end;
        end;
    end;

    list.Add('');
    list.Add('Fbasic_blocks');
    s := '';
    SetLength( LArray,0);

    InitDFSFalseTraverse;
    while True do
    begin

         bb_ea := DFSFalseTraverseBlocks;
         if bb_ea = UInt64(-1) then Break;

         prinBlock(bb_ea);

         UpdateAddTodo(bb_ea);
         LArray := LArray + [bb_ea];

    end;

    if lPrintBBAddr then
    begin
        list.Add('=========== Basic Blocks:') ;
        for bb_ea in LArray do
        begin
             s  := 'Basic Block Head: '+IntToHex(bb_ea,4) ;
             list.Add(s);
        end;
    end;

    list.SaveToFile('debugLog.Txt');
end;

procedure TCFG_Analysis.InitDFSFalseTraverse;
begin
    SetLength(Faddr_todo,0);
    Faddr_done.Clear;
    Faddr_todo := Faddr_todo + [Fstart_ea] ;
    FConsumeCall := Ffunction_calls;
end;

procedure TCFG_Analysis.UpdateAddTodo(ea: UInt64);
var
  x,n  : UInt64;
  refs : TDictionary<UInt64,Boolean>;
begin
    if (Fbasic_blocks.ContainsKey(ea)) and (Length(Fbasic_blocks[ea]) > 0) then
    begin
        refs := Frefs_from[ Fbasic_blocks[ea][High(Fbasic_blocks[ea])].OriginEA ];

        for x in refs.Keys do
        begin
            if (x <> 0) and (refs[x] = True) then
                Faddr_todo := Faddr_todo + [x];
        end;

        for x in refs.keys do
        begin
            if (x <> 0) and (refs[x] = False) then
                Faddr_todo := Faddr_todo + [x];
        end;

        // evita che i jmp confondano l'ordine di esecuzione dei vari BB
        if (FDisAsm.IsJmp( Fbasic_blocks[ea][High(Fbasic_blocks[ea])].Insn)) and (ea <> Fstart_ea)  then
        begin
             try
               X    := refs.Keys.ToArray[0];
               if Frefs_to.ContainsKey(X) and (X <> 0)then // and (X <> 0) modifica 21/07/2018
               begin
                   refs := Frefs_to[ X ];
                   if refs.Count > 1 then
                   begin
                       for n := 0 to refs.Count -1  do
                       begin
                            if refs.Keys.ToArray[n] <> Faddr_todo[ High(Faddr_todo) ] then
                            begin
                                x := DFSBBSearchHead(refs.Keys.ToArray[n]);
                                if not FDisAsm.IsCFI( Fbasic_blocks[x][High(Fbasic_blocks[x])].Insn) then
                                begin
                                    SetLength(Faddr_todo,Length(Faddr_todo)-1 );
                                    Break;
                                end;
                            end;
                       end;
                   end;
               end;
             except
               OutDbg('>Function:DFSFalseTraverseBlocks. Jmp Fix Failed!!');
             end;
        end;
    end else
    begin
        OutDbg( '>Function:DFSFalseTraverseBlocks - WEIRD! block ref missing!');

        for x in __refs.keys do
        begin
            if x = 0 then  continue
            else if not __refs.ContainsKey(x) then
            begin
                OutDbg( Format('>Function:DFSFalseTraverseBlocks - ERROR: __refs NO key [%08x]',[x]));
                continue
            end
            else if __refs[x] = True then
                Faddr_todo := Faddr_todo + [x];
        end;
    end;

end;

function TCFG_Analysis.DFSFalseTraverseBlocks:  UInt64;
        (*
            TraverseBlocks and at every block call callback(block_ea).
            callback - function
        '*)
var
  ea : UInt64;
begin

    if Fstart_ea = 0 then Exit(UInt64(-1));

    Result := UInt64(-1);
    while Length(Faddr_todo) > 0 do
    begin
        ea := Faddr_todo[High(Faddr_todo)];
        SetLength(Faddr_todo,Length(Faddr_todo) - 1);

        if (Faddr_done.ContainsKey(ea))  or (ea = 0) then continue ;

        Faddr_done.Add(ea, 1);

        OutDbg( Format('">Function:DFSFalseTraverseBlocks - Analysis @ [%08x]',[ea]));

        try
          __refs.Free;
          __refs := TDictionary<UInt64,Boolean>.Create( Frefs_from[ Fbasic_blocks[ea][High(Fbasic_blocks[ea])].OriginEA ] )
        except
            OutDbg( Format('Exception %08x head %08x ',[ea,Fstart_ea]));
        end;
        Exit( ea );
    end;

    while Length(FConsumeCall) > 0 do
    begin
        ea := FConsumeCall[High(FConsumeCall)];
        SetLength(FConsumeCall,Length(FConsumeCall) - 1);

        if (Faddr_done.ContainsKey(ea))  or (ea = 0) then continue ;

        Faddr_done.Add(ea, 1);

        OutDbg( Format('">Function:DFSFalseTraverseBlocks - Analysis CALL @ [%08x]',[ea]));
        Exit( ea );

    end;

end;

function  TCFG_Analysis.DFSBBSearchHead(find_addr: UInt64): UInt64;
        (*
            Find head (start) of basic block that has find_addr as an element.

            NOTE: use heuristic that you can discharge/stop analysis when you
                find self.basic_blocks.has_key(head), either addr belogns to
                that block (code path) or not.
            Return: Head of BB that find_addr belongs to.
        *)
var
  addr_todo    : TArray<UInt64>;
  addr_done    : TRef;
  ea,bb_ea,addr: UInt64;
  instr,item   : TCfGIns;
  found        : Boolean;
begin
    OutDbg( Format('>Function:DFSBBSearchHead - Searching for block head @ [%08x]',[find_addr]));

    addr_todo := addr_todo + [find_addr] ;
    addr_done := TDictionary<UInt64,Boolean>.Create;

    while Length(addr_todo) > 0 do
    begin
        ea := addr_todo[High(addr_todo)];
        SetLength(addr_todo,Length(addr_todo) - 1);

        if (addr_done.ContainsKey(ea))  or (ea = 0) then continue ;

        addr_done.Add(ea, True);

        if Fbasic_blocks.ContainsKey(ea) then
        begin
            for instr in Fbasic_blocks[ea] do
              if instr.OriginEA = find_addr then
                 Exit(ea) ;
        end;
        if ea = Fstart_ea then
           continue ;

        //try to save the situation
        if not Frefs_to.ContainsKey(ea) then
        begin
            for bb_ea in Fbasic_blocks.keys  do
            begin
                for item in Fbasic_blocks[bb_ea] do
                    if item.OriginEA = find_addr then Exit(bb_ea);
            end;
        end;

        for addr in Frefs_to[ea].Keys do
        begin
            if Fbasic_blocks.ContainsKey(addr) then
            begin
                found := False;
                for instr in self.basic_blocks[addr] do
                begin
                    found := True;
                    if instr.OriginEA = find_addr then
                    begin
                        Exit(addr);
                    end;
                end;
                if not found then
                begin
                    addr_todo := addr_todo + [addr] ;
                end;
            end else
            begin
                addr_todo := addr_todo + [addr] ;
            end;
        end;
    end;
    Result := 0;

end;

function TCFG_Analysis.GetIstruzioneItem(Addr: UInt64; var Bb_Head: UInt64; var idx : Integer): TCfGIns;
var
 vAddr: UInt64;
 i    : Integer;
 item : TCfGIns;
begin
     vAddr   := DFSBBSearchHead(Addr);
     Bb_Head := vAddr;

     if vAddr  = 0 then
       raise exception.Create(Format('>Function:GetIstruzioneItem - Error on Search @ [%08x] ',[Addr]));

     i   := 0;
     idx := i;
     for item in Fbasic_blocks[vAddr] do
     begin
         if item.OriginEA =  Addr then
         begin
              idx := i ;
              Exit( item);
         end;
         inc(i);
     end;

end;

procedure TCFG_Analysis.SplitBlock( split_addr: UInt64);
        (*
            Split basic block @ split_addr and create a new basic_blocks[]
            entry.
        *)
var
  bb_head,orig_head : UInt64;
  instr             : TCfGIns;
  tmpIns            : TIns;

begin
    OutDbg( Format('>Function:SplitBlock - Entry splitting @ [%08x] ',[split_addr]));

    if Fbasic_blocks.ContainsKey(split_addr) then Exit;

    bb_head := split_addr;

    orig_head := DFSBBSearchHead(split_addr);
    if orig_head = 0 then
    begin
        OutDbg(Format('>Function:SplitBlock - Failed @ [%08x]: orig_head=None ',[split_addr]));
       // raise Exception.Create('SplitBlock: orig_head not found');
    end;

    OutDbg(Format('>Function:SplitBlock - Got orig_head [%08x] ',[orig_head]));
    // Create new BBlock
    Fbasic_blocks.Add(bb_head,[]) ;
    if Length(Fbasic_blocks[orig_head]) > 0 then
    begin
        tmpIns:= Fbasic_blocks[orig_head];
        instr := tmpIns[ High(Fbasic_blocks[orig_head]) ];
        SetLength(tmpIns, Length(Fbasic_blocks[orig_head])-1);
        Fbasic_blocks[orig_head] := tmpIns;
    end
    else
        Exit;

    while True do
    begin
        tmpIns:= Fbasic_blocks[orig_head];
        Insert(instr,tmpIns,0 );
        Fbasic_blocks[orig_head] := tmpIns;
        if instr.OriginEA = bb_head then break ;

        tmpIns:= Fbasic_blocks[orig_head];
        instr := tmpIns[ High(Fbasic_blocks[orig_head]) ];
        SetLength(tmpIns, Length(Fbasic_blocks[orig_head])-1);
        Fbasic_blocks[orig_head] := tmpIns;
    end;
    OutDbg(Format('>>Function:SplitBlock - Split @ [%08x]; original @ [%08x]',[split_addr,orig_head]));
end;

procedure TCFG_Analysis.AssertCFGStructure;
 (*
     Make sure that CFG structure conforms with basic block rules.
     First we iterate trough whole CFG and split any blocks that have
     code references to the middle of the block.
     Used for debugging.
 *)
var
  addr_todo   : TArray<UInt64>;
  addr_done   : TRef;
  ea,addr_ref,
  addr        : UInt64;
  last_i,
  first_i,Ist : TCfGIns;
  i           : Integer;

begin
    if Fstart_ea = 0 then Exit;

    OutDbg(Format('>Function:AssertCFGStructure - Starting TraverseBlocks @ [%08x] ',[Fstart_ea]));

    addr_todo := addr_todo + [Fstart_ea] ;
    addr_done := TDictionary<UInt64,Boolean>.Create;

    while Length(addr_todo) > 0 do
    begin
        ea := addr_todo[High(addr_todo)];
        SetLength(addr_todo,Length(addr_todo) - 1);

        if (addr_done.ContainsKey(ea)) or (ea = 0) then  Continue;

        addr_done.Add(ea,True) ;

        if not Fbasic_blocks.ContainsKey(ea) then
        begin
            SplitBlock(ea);
        end;

        //check to see if there is isCFI() instruction other than last one
        last_i  := Fbasic_blocks[ea][High(Fbasic_blocks[ea])];
        first_i := Fbasic_blocks[ea][0];

        i := 0;
        repeat
            if Length(Fbasic_blocks[ea]) < 1 then Break;

            Ist :=  Fbasic_blocks[ea][i];

            if Ist.OriginEA = Fstart_ea then   break;

            with FDisAsm,Ist do
            if ( (IsCFI(Insn)) and (not IsCall(Insn)) and (not IsLoop(Insn)) and (OriginEA <> last_i.OriginEA) ) or ( (GetRefsTo(OriginEA).Count > 1) and (OriginEA <> first_i.OriginEA) ) then
            begin
                SplitBlock(Ist.OriginEA) ;
            end;

            Inc(i);
        until  i > Length(Fbasic_blocks[ea]) - 1;

        try
            addr_ref := Fbasic_blocks[ea][High(Fbasic_blocks[ea])].OriginEA
        except
            raise Exception.Create('>Function:AssertCFGStructure');
        end;
        if addr_ref = 0 then continue;

        for addr in Frefs_from[ addr_ref ].Keys do
        begin
            if (addr <> 0) and (not Fbasic_blocks.ContainsKey(addr)) then
            begin
                SplitBlock(addr)
            end;
        end;
        addr_todo := addr_todo + Frefs_from[ addr_ref ].keys.ToArray;
    end;
end;

procedure TCFG_Analysis.startAnalysis(startEA: UInt64);
      (*
      Begins translation.
      *)
var
  lstTmp           : TIns;
  prev_block_ea,ea : UInt64;
  idx              : Integer;

begin
    SetLength(lstTmp,0);

    FListaIstr  := GetContextCode(startEA, FFakeJJTable);
   { var test : TFunctionAnalysisState := TFunctionAnalysisState.Create(DisAsm.NomeFile,DisAsm);
    var tListaIstr        : TLinkedList<TCpuIstruz>;
    tListaIstr := test.GetContextCode(startEA) ;    }

    FEmulateCall:= 0;

    if startEA <> 0 then
    begin
        Faddr_todo := Faddr_todo + [startEA];
        if Fstart_ea = 0 then   Fstart_ea      := startEA
        else                    Fcurrent_block := startEA;

        Fcurrent_block := startEA;
        Fbasic_blocks.Add(startEA, lstTmp);
    end;
    prev_block_ea := Fcurrent_block;

    while Length(Faddr_todo) > 0 do
    begin
        ea := Faddr_todo[High(Faddr_todo)];
        SetLength(Faddr_todo,Length(Faddr_todo) - 1);

        if ea = 0  then Continue;

        TArray.Sort<UInt64>(Ffunction_calls);
        if TArray.BinarySearch<UInt64>(Ffunction_calls,ea, idx) then
            Fcurrent_block := 0;

        if Faddr_done.ContainsKey(ea) then
        begin
            OutDbg(Format('>Function:startAnalysis - !Skipping over @ %08x',[ea]));
            Fcurrent_block := 0 ;
            continue
        end;
        Faddr_done.Add(ea, uint64(-1));         //unknown currently

        Faddr_appended_len := fillInstructionData(ea) ;

        //After we build a BB we optimize it
        if Fcurrent_block <> prev_block_ea then
            prev_block_ea := Fcurrent_block

    end;
    OutDbg(Format('>Function:startAnalysis - !Elaborati %08x Istruzioni',[FCountLine]));
    FNumBB := Fbasic_blocks.Count;
    Faddr_appended_len := 0 ;

    AssertCFGStructure ;
    {$IFDEF TESTING}
    PrintDebugInfo;
    {$ENDIF}
end;


function TCFG_Analysis.fillInstructionData(ea: UInt64): UInt64;
        (*
        Populate instruction information.
        Add self.addr_todo info.
        *)
var
  refs_appended,
  create_new_bb : Word;
  new_instr     : TCfGIns;
  refs,refs_to  : TArray<UInt64>;
  ref,next_ea,
  uPushImm      : UInt64;
  nextID        : Cardinal;
  lstTmp        : TIns;

begin
     OutDbg(Format('>Function:_fillInstructionData - Filling @ [%08x]',[ea]));

     refs_appended  := 0;
     ZeroMemory(@new_instr,SizeOf(cs_insn) );

     SetLength(lstTmp,0);

     FDisAsm.DisAssembleVA(ea);
     //should we create new basic block
     create_new_bb := 0;

     if Fcurrent_block = 0 then
     begin
        Fcurrent_block := ea;
        Faddr_done.AddOrSetValue(ea,Fcurrent_block);
     end;

     refs_to := CodeRefsTo(ea, True);
     if (Length(refs_to) > 1) and (ea <> Fstart_ea) then
     begin
        //this is a case when there are refs_to but we already created new bb
        if Fcurrent_block <> ea then
           Fcurrent_block := ea;
     end;

     refs := CodeRefsFrom(ea, True);

     new_instr.OriginEA := ea;

     //what to add to addr_todo
     if FDisAsm.IsCall then
     begin
        if Length(refs) < 2 then
        begin
            OutDbg(Format('">Function:_fillInstructionData - CALL instr @ [%08x]',[ea]));
            // refs.Count = 1 un riferimento Mancante, 2 cases  - Call +$0
            if FDisAsm.BranchDestination = FDisAsm.address + FDisAsm.Size then
            begin
                // su x64 è errore push imm64 ma per oreans va bene perchè è utilizzato solo in vmentry e posso recuperalo anche quando il VA è maggiore di $FFFFFFFF
                if FDisAsm.BranchDestination < $FFFFFFFF then
                   new_instr.Insn := ACAssembleCpuI('push '+'0x'+IntToHex(FDisAsm.address + FDisAsm.Size), FDisAsm.Insn, FDisAsm.Mode);
                // se x64 e VA > $FFFFFFFF inserisco indirizzo nella lista per poterlo recuperare
                if FDisAsm.BranchDestination > $FFFFFFFF then
                    FFakeCallX64Safe :=  FFakeCallX64Safe + [ FDisAsm.BranchDestination ];

                Faddr_todo  := Faddr_todo + [refs[0]];
                refs_appended := refs_appended + 1;

                 //Fill CFG info
                 AddRefsTo(refs[0], ea, False);
                 AddRefsFrom(ea, refs[0], False);
            end
            // refs.Count = 1  - NOTE: special case, if call(exit) then normal code flow is empty
            else if Length(CodeRefsFrom(ea, False)) > 0 then
            begin
                Ffunction_calls := Ffunction_calls + [FDisAsm.BranchDestination];

                //Fill CFG info
                AddRefsTo(0, ea, False) ;
                AddRefsFrom(ea, 0, False) ;

                create_new_bb := 1
            end else
            // refs.Count = 0
            begin
                //This is a case when call destination is unresolvable (eg. call eax)
                Faddr_todo  := Faddr_todo + [refs[0]];
                refs_appended := refs_appended + 1;

                Ffunction_calls := Ffunction_calls + [FDisAsm.BranchDestination];

                //Fill CFG info
                AddRefsTo(refs[0], ea, False);
                AddRefsFrom(ea, refs[0], False);

                //raise RefResolver
            end;
        end else
        // 2 riferimenti,Tutto regolare
        begin
            OutDbg('>Function:_fillInstructionData - call xxx..');

            Insert(refs[1],Faddr_todo,0);
            Faddr_todo  := Faddr_todo + [refs[0]];

            refs_appended := refs_appended + 1;

            Ffunction_calls := Ffunction_calls +[refs[1]];

            //Fill CFG info
            AddRefsTo(refs[0], ea, False);
            AddRefsFrom(ea, refs[0], False) ;

            AddRefsTo(refs[1], ea, True);
            AddRefsFrom(ea, refs[1], True)
        end;
     end
     else if FDisAsm.IsJmp then
     begin
         OutDbg(Format('>Function:_fillInstructionData - JMP @ [%08x]',[ea]));
         //NOTE: Riferimento non risolvibile (eg. jmp eax)
         if Length(refs) = 0 then
         begin
             create_new_bb := 1;

             //Fill CFG info
             AddRefsTo(0, ea, True);
             AddRefsFrom(ea, 0, True);

             //raise RefResolver
         end
         //più di un riferimento - NOTE: switch jump
         else if (Length(refs) > 1) and (FDisAsm.Insn.operands[0].tipo = T_MEM) then
         begin
             if FDisAsm.ResolveOpValue(0) <> 0 then
             begin
                 Faddr_todo    := Faddr_todo    + refs;
                 refs_appended := refs_appended + Length(refs);

                 create_new_bb := 1;
                  //add first ref as a "default" jmp
                 for ref in refs do
                 begin
                     AddRefsTo(ref, ea, True)   ;
                     AddRefsFrom(ea, ref, True)
                 end;
             end
             else
                 raise Exception.Create('jump Undefinid');
         end else
         // Un riferimento -Tutto regolare
         begin
             if ea = Fstart_ea then
                Fstart_ea    := refs[0];

             Faddr_todo  := Faddr_todo + [refs[0]];
             refs_appended := refs_appended + 1;
             create_new_bb := 1;

             //Fill CFG info
             AddRefsTo(refs[0], ea, True);
             AddRefsFrom(ea, refs[0], True);

             //check if jmp is loop?
         end;
     end
     else if FDisAsm.IsJcc then
     begin
         OutDbg(Format('>Function:_fillInstructionData - JCC @ [%08x]',[ea]));

          //Opaque predicates
          if FFakeJJTable.ContainsKey(ea) then
          begin
              OutDbg(Format('>Function:_fillInstructionData - Opaque predicates @ [%08x]',[ea]));
              if not FFakeJJTable[ea] then
              begin
                  create_new_bb  := 1;
                  AddRefsTo(refs[0], ea, False);
                  AddRefsFrom(ea, refs[0], False);
                  Faddr_todo    := Faddr_todo + [refs[0]];

                  new_instr.Insn := ACAssembleCpuI('jmp '+'0x'+IntToHex(refs[0]), FDisAsm.Insn,FDisAsm.Mode);
              end else
              begin
                  create_new_bb := 1;
                  // una referenza può mancare nel caso di trasformazione in jmp saltando a addr+ size
                  if Length(refs) > 1 then
                  begin
                      AddRefsTo(refs[1], ea, True);
                      AddRefsFrom(ea, refs[1], True);
                      Faddr_todo     := Faddr_todo + [refs[1]];
                      new_instr.Insn := ACAssembleCpuI('jmp '+'0x'+IntToHex(refs[1]), FDisAsm.Insn,FDisAsm.Mode);
                  end else
                  begin
                      AddRefsTo(refs[0], ea, True);
                      AddRefsFrom(ea, refs[0], True);
                      Faddr_todo     := Faddr_todo + [refs[0]];
                      new_instr.Insn := ACAssembleCpuI('jmp '+'0x'+IntToHex(refs[0]), FDisAsm.Insn,FDisAsm.Mode);
                  end;

              end;
              refs_appended := refs_appended + 1;
          end else
          begin
              //add CFG edges
              //add normal (False) confition destination
              AddRefsTo(refs[0], ea, False);
              AddRefsFrom(ea, refs[0], False) ;

              //add True condition destination
              //yes, this case is not always true (jcc $+5)
              if Length(refs) > 1 then
              begin
                  AddRefsTo(refs[1], ea, True);
                  AddRefsFrom(ea, refs[1], True);
              end;

              create_new_bb := 1;
              //check destination (loop or new block)
              if Length(refs) <> 2 then
                OutDbg(Format('>Function:_fillInstructionData - !WARRNING @ [%08x] JCC with =%d refs [%s]',[ea,Length(refs),FDisAsm.CmdStr]));

              Faddr_todo    := Faddr_todo    + refs;
              refs_appended := refs_appended + Length(refs);
          end;
     end else
     begin
         if Length(refs) > 1 then
         begin
             //eg. loopxx
             OutDbg(Format('>Function:_fillInstructionData - !WARRNING @ [%08x] instr with >1 refs [%s] len(refs)=[%d]',[ea,FDisAsm.CmdStr,Length(refs)]));
             create_new_bb := 1 ;
             //add CFG edges, example instr LOOP
             //add normal (False) confition destination
             AddRefsTo(refs[0], ea, False);
             AddRefsFrom(ea, refs[0], False);

             //add True condition destination
             AddRefsTo(refs[1], ea, True) ;
             AddRefsFrom(ea, refs[1], True);
         end
         else if Length(refs) = 0 then
         begin
             OutDbg(Format('>Function:_fillInstructionData - !WARRNING @ [%08x] instr with 0 refs [%s]',[ea,FDisAsm.CmdStr]));
             create_new_bb := 1 ;
             //add CFG edges
             AddRefsTo(0, ea, True) ;
             AddRefsFrom(ea, 0, True) ;
         end else
         begin
             //regular instruction, one ref_from
             next_ea := ea + FDisAsm.Size;
             FDisAsm.DisAssembleVA(next_ea) ;
             nextID  := FDisAsm.Id;

             FDisAsm.DisAssembleVA(ea) ;
             uPushImm  := FDisAsm.Insn.operands[0].imm.U;

             if (FDisAsm.Id = Ord(X86_INS_PUSH)) and (FDisAsm.Insn.operands[0].tipo = T_IMM ) and (nextID = Ord(X86_INS_RET)) then
             begin
                 new_instr.Insn := ACAssembleCpuI('jmp '+'0x'+IntToHex(uPushImm), FDisAsm.Insn,FDisAsm.Mode);

                 AddRefsTo(uPushImm, ea, False) ;
                 AddRefsFrom(ea, uPushImm, False) ;

                 refs := [];
                 refs := refs + [ uPushImm ] ;
                 create_new_bb := 1;

             end
             //should be false in most cases
             else if (FDisAsm.Id = Ord(X86_INS_RET)) then
             begin
                 //add CFG edges
                 AddRefsTo(0, ea, True) ;
                 AddRefsFrom(ea, 0, True) ;

                 create_new_bb := 1;

             end else
             begin
                 // Check if this instruction is != ring3

                 if (FreplaceRingNot3 = True) and (FDisAsm.IsUnusual = True) and ( FDisAsm.Id <> Ord(X86_INS_RDTSC))then
                 begin
                     //print "Removing Ring!3[%s]" % repr(idc.GetDisasm(ea))
                     new_instr.Insn := ACAssembleCpuI('retn', FDisAsm.Insn,FDisAsm.Mode);

                     if Fbasic_blocks.ContainsKey(Fcurrent_block) then
                         Fbasic_blocks[Fcurrent_block] := Fbasic_blocks[Fcurrent_block] + [ new_instr ]
                     else begin
                          SetLength(lstTmp,0);
                          lstTmp := lstTmp + [ new_instr ];
                          Fbasic_blocks.Add(Fcurrent_block,lstTmp) ;
                     end;

                     Fcurrent_block := 0 ;
                     Ffake_ret      := Ffake_ret + [ea];

                     //Add references to CFG
                     AddRefsTo(0, ea, True);
                     AddRefsFrom(ea, 0, True) ;

                     Exit(refs_appended); //done with current instruction
                 end;
                 AddRefsTo(refs[0], ea, False);
                 AddRefsFrom(ea, refs[0], False) ;
             end;
             //common case, extend DFS list
             //if mnem.find("ret") < 0:
             Faddr_todo    :=  Faddr_todo +  refs;
             refs_appended := refs_appended + Length(refs);
         end;
     end;
     // syncronize
     if new_instr.Insn.OpCode.mnem =  Ord(X86_INS_INVALID) then
       new_instr.insn := FDisAsm.insn ;

     if Fbasic_blocks.ContainsKey(Fcurrent_block) then
         Fbasic_blocks[Fcurrent_block] := Fbasic_blocks[Fcurrent_block] + [ new_instr ]
     else begin
          SetLength(lstTmp,0);
          lstTmp := lstTmp + [ new_instr ];
          Fbasic_blocks.Add(Fcurrent_block,lstTmp) ;
     end;

     if create_new_bb = 1 then
         Fcurrent_block := 0 ;

     Result := refs_appended;
end;

function TCFG_Analysis.RemoveInstruction(ea: UInt64; bb_ea: UInt64 = 0):Boolean;
 (*
     TODO
 *)
var
  bb_len,location,
  old_bb_len      : Cardinal;
  new_bb_head,
  last_ea         : UInt64;
  refs_from,
  refs_to         : TList<TRef>;
  test            : TCfGIns;
  idxFound        : Integer;
  tmpIns          : TIns;
begin
     Result := False;
     if bb_ea = 0 then
         bb_ea := DFSBBSearchHead(ea) ;

     if ea = $5CC2B5 then
         ea := ea;

     bb_len := Length(Fbasic_blocks[bb_ea]);
     for location := 0 to bb_len - 1 do
     begin
         if Fbasic_blocks[bb_ea][location].OriginEA = ea then
         begin
             refs_from := GetRefsFrom(ea);

             if refs_from.Count > 1 then
             begin
                 raise Exception.Create('Function:RemoveInstruction');
             end;
             test   := Fbasic_blocks[bb_ea][location] ;
             tmpIns := Fbasic_blocks[bb_ea];
             Delete(tmpIns,location,1 ) ;
             Fbasic_blocks[bb_ea] := tmpIns ;
             old_bb_len := Length(Fbasic_blocks[bb_ea]);
             DelRefs(ea) ;
             Result := True;

             OutDbg( Format('>Function:RemoveInstruction - mnem[%s] ea[%08x]',[test.Insn.OpCode.ToString,test.OriginEA]));

             if (location = 0) and (ea = Fstart_ea) then
                 break
             else if (location = 0) and (old_bb_len > 0) then
             begin
                 try
                     new_bb_head := Fbasic_blocks[bb_ea][0].OriginEA;
                     // modificare anche il riferimento
                     while FindArrayVal(Faddr_todo,bb_ea,idxFound) do
                        Faddr_todo[idxFound] := new_bb_head;
                 except
                     raise  Exception.Create('print hex(ea), hex(bb_ea)');
                 end;
                 Fbasic_blocks.Add(new_bb_head,Fbasic_blocks[bb_ea]);// := Fbasic_blocks[bb_ea] ;

                 Fbasic_blocks.Remove(bb_ea)  ;
             end
             else if location = 0 then
             begin
                  Fbasic_blocks.Remove(bb_ea);
             end
             else if (location = (bb_len-1)) and (Length(Fbasic_blocks[bb_ea]) > 0) then
             begin
                 //in this case try to merge blocks
                 last_ea   := self.basic_blocks[bb_ea][High(self.basic_blocks[bb_ea])].OriginEA;
                 refs_from := GetRefsFrom(last_ea);

                 if refs_from.Count <> 1 then
                     Exit(False) ;

                 refs_to := GetRefsTo(refs_from[0].Keys.ToArray[0]);

                 if refs_to.Count = 1 then
                 begin
                     if Fbasic_blocks.ContainsKey(refs_from[0].Keys.ToArray[0])then
                     begin
                         //Fbasic_blocks[bb_ea].AddRange( Fbasic_blocks[ refs_from[0].Keys.ToArray[0] ].ToArray);
                         Fbasic_blocks[bb_ea] := Fbasic_blocks[bb_ea] +  Fbasic_blocks[ refs_from[0].Keys.ToArray[0] ] ;

                         Fbasic_blocks.Remove( refs_from[0].Keys.ToArray[0] ) ;
                     end
                     else if (refs_from[0].Keys.ToArray[0] = 0) then
                         //pass
                     else
                         raise Exception.Create('RemoveInstruction1');
                 end;
             end;
             break
         end;

     end;

end;

procedure TCFG_Analysis.DelRefs(ref_remove: UInt64);
 (*
     Delete intermediary node eg. 1->2->3 => 1->3
 *)
var
  ref_from,ref_to  : UInt64;
  newIstr  : TCfGIns;
  item     : TCfGIns;
  bb_Head  : UInt64;
  oldref   : TList<TRef>;
  iIdx     : Integer;
  tmpIstr  : TCpuIstruz;

begin
     if Frefs_from[ref_remove].Count <> 1 then
         raise Exception.Create('DelRefs');

     ref_from := Frefs_from[ref_remove].keys.ToArray[0];

     OutDbg( Format('>Function:DelRefs - Function start ea [%08x]',[Fstart_ea]));

     if (ref_remove <> Fstart_ea) and (not Frefs_to.ContainsKey(ref_remove)) then
     begin
         OutDbg( '>Function:DelRefs - CFG State inconsitency! It''s not a bug if there was undefined code but if you can share sample please send for examination!');
         Exit;
     end;


     try

       //start by establishin references from blink<->flink
       //if this instruction is function head, skip this case and make next reference function head
       if ref_remove <> Fstart_ea then
       begin
           for ref_to in Frefs_to[ref_remove].Keys do
           begin
               oldref := GetRefsFrom(ref_to);

               AddRefsFrom(ref_to,   ref_from, Frefs_from[ref_to][ref_remove]);
               AddRefsTo  (ref_from, ref_to,   Frefs_to[ref_remove][ref_to]);
               // aggiorna istruzione nel caso di jcc
               if oldref.Count > 0 then
               begin
                   item := GetIstruzioneItem(ref_to,bb_Head,iIdx) ;
                   if FDisAsm.IsCFI(item.Insn) then
                   begin
                        if (FDisAsm.BranchDestination(item.Insn) <> 0) and (FDisAsm.BranchDestination(item.Insn) = ref_remove)then
                        begin
                            tmpIstr.address := ref_to;
                            newIstr.Insn    := ACAssembleCpuI(item.Insn.OpCode.ToString + ' 0x'+ IntToHex(ref_from), tmpIstr,FDisAsm.Mode);
                            newIstr.OriginEA:= ref_to;
                            Fbasic_blocks[bb_Head][iIdx] :=  newIstr;
                            // cambiare riferimente anche nella call può capitare Call 0x123; 0x123:jmp 0x444
                            while FindArrayVal(Ffunction_calls,ref_remove,iIdx) do
                                 Ffunction_calls[iIdx] := ref_from;

                        end;
                   end;
               end;
           end;
       end;
       //if this is function head, declare ref_from new function head
       if Fstart_ea = ref_remove then
       begin
           Fstart_ea := ref_from
       end else
       begin
           //if not delete all references to ref_remove
           for ref_to in Frefs_to[ref_remove].Keys do
           begin
               refs_from[ref_to].Remove(ref_remove);
           end;
       end;
       //
       for ref_from in Frefs_from[ref_remove].Keys   do
       begin
           Frefs_to[ref_from].Remove(ref_remove);
       end;

       if Frefs_to.ContainsKey(ref_remove) then
           Frefs_to.Remove(ref_remove);
       if Frefs_from.ContainsKey(ref_remove) then
           Frefs_from.Remove(ref_remove);
       if Faddr_done.ContainsKey(ref_remove) then
           Faddr_done.Remove(ref_remove);
     finally

     end;

end;

(********************************************)
//////////// Analyze context+Opaque Predicates
(********************************************)
procedure TCFG_Analysis.Add_I(const istruz: TCpuIstruz; var list: TLinkedList<TCpuIstruz>;lDeleteLast: Boolean);
var
  tmp   : TCpuIstruz;
  tmpLst: TArray<UInt64>;
begin
    ZeroMemory(@tmp,SizeOf(TCpuIstruz));
    tmp := istruz;
    list.AddLast(tmp);

    // aggiungere refto per velocizzare fillistruzione
    //TODO mem address
    if FDisAsm.BranchDestination(istruz) <> 0 then
    begin
        // calll $+5
        if (FDisAsm.IsCall(istruz)) and ( FDisAsm.BranchDestination(istruz) = (istruz.address + (istruz.size)))  then
          Exit;

        //refTo
        if FFastRefTo.ContainsKey(FDisAsm.BranchDestination(istruz)) then
        begin
            if not lDeleteLast then
               FFastRefTo[FDisAsm.BranchDestination(istruz)] := FFastRefTo[FDisAsm.BranchDestination(istruz)] + [istruz.address]
            else begin
                if FFastRefTo.ContainsKey(FDisAsm.BranchDestination(istruz)) then
                begin
                     FFastRefTo[FDisAsm.BranchDestination(istruz)] := FFastRefTo[FDisAsm.BranchDestination(istruz)] + [istruz.address]
                end else
                begin
                    SetLength(tmpLst,0);
                    tmpLst := tmpLst + [Istruz.address];
                    FFastRefTo.Add(FDisAsm.BranchDestination(istruz),tmpLst)
                end;
            end;
        end else
        begin
            SetLength(tmpLst,0);
            tmpLst := tmpLst + [Istruz.address];
            FFastRefTo.Add(FDisAsm.BranchDestination(istruz),tmpLst)
        end;

        //reFrom
        if FFastRefFrom.ContainsKey(istruz.address) then
        begin
            if not lDeleteLast then
               FFastRefFrom[istruz.address] := FFastRefFrom[istruz.address] +[FDisAsm.BranchDestination(istruz)]
            else
                FFastRefFrom[istruz.address][High(FFastRefFrom[istruz.address])] := FDisAsm.BranchDestination(istruz);
        end else
        begin
            SetLength(tmpLst,0);
            tmpLst := tmpLst + [ FDisAsm.BranchDestination(istruz) ];
            FFastRefFrom.Add(istruz.address,tmpLst)
        end;

    end;
end;

function TCFG_Analysis.GetContextCode(VAAddr: UInt64; var ctxFakeJccT: TRef): TLinkedList<TCpuIstruz>;
var
  FListaIstr  : TLinkedList<TCpuIstruz> ;
  node        : CFNode;
  ea          : UInt64;
  AddrToDo    : TArray<UInt64>;
  AddrDone    : TRef;
  IsOpPredict,
  isJccExecute: Boolean;
  new_instr   : TCpuIstruz;
  lDeleteLast : Boolean;

  lstOpPred   : TStringList;

begin
     FCountLine := 0;
     FNumOP     := 0;
     FListaIstr := TLinkedList<TCpuIstruz>.Create;

     ZeroMemory(@new_instr,SizeOf(cs_insn) );

     AddrDone := TDictionary<UInt64,Boolean>.Create;
     node     := CFNode.Create(VAAddr,VAAddr,VAAddr);
     ctxFakeJccT.Clear;
     FFastRefTo.Clear;

     try
         lstOpPred     := TStringList.Create;

         AddrToDo := AddrToDo + [VAAddr];
         while Length(AddrToDo) > 0 do
         begin
             ea := AddrToDo[High(AddrToDo)];
             SetLength(AddrToDo,Length(AddrToDo) - 1);
             node.brtrue := 0;
             node.brfalse:= 0;
             lDeleteLast := False;

             if AddrDone.ContainsKey(ea) then Continue;
             AddrDone.Add(ea,False);

             inc(FCountLine);

             if AddrDone.Count > 200000 then
             begin
                 OutDbg( '>Function:RecursiveDisAsm - Pass 200000 instructions|||. Stopping||');
                 Continue;
             end;

             node.icount := node.icount + 1;
             if not FDisAsm.DisAssembleVA(ea) then
             begin
                  AddrToDo := AddrToDo + [ea + 1] ;
                  Continue
             end;
             // Add Instruction to list
             Add_I(FDisAsm.Insn,FListaIstr,lDeleteLast);

             if FDisAsm.IsCFI  then
             begin

                  // Gestione Opaque Predicates qui per evitare di esegure il disasm all'infinito
                  if FDisAsm.IsJcc then
                  begin
                      if FListaIstr.Count > 1 then
                      begin
                          FListaIstr.DeleteLast;
                          lDeleteLast := True; // notifica per no reinserimento riferimento
                      end else
                      begin
                          ctxFakeJccT.AddOrSetValue(ea,True);
                          node.brtrue := FDisAsm.BranchDestination ;
                          // trasform to jmp
                          new_instr := ACAssembleCpuI('jmp '+'0x'+IntToHex(node.brtrue), FDisAsm.Insn,FDisAsm.Mode);
                          if node.brtrue  <> 0 then AddrToDo := AddrToDo + [node.brtrue];
                          Add_I(new_instr,FListaIstr,lDeleteLast);

                          Continue
                      end;

                      IsOpPredict := OpPredicate(FListaIstr,FDisAsm.id,isJccExecute);
                      if IsOpPredict then
                      begin
                           inc(FNumOP);
                           if isJccExecute then
                           begin
                               ctxFakeJccT.AddOrSetValue(ea,True);
                               node.brtrue := FDisAsm.BranchDestination ;
                               // trasform to jmp
                               new_instr := ACAssembleCpuI('jmp '+'0x'+IntToHex(node.brtrue), FDisAsm.Insn,FDisAsm.Mode);
                           end else
                           begin
                               ctxFakeJccT.AddOrSetValue(ea,False);
                               node.brtrue := ea + FDisAsm.Size;
                               // trasform to jmp
                               new_instr := ACAssembleCpuI('jmp '+'0x'+IntToHex(node.brtrue), FDisAsm.Insn,FDisAsm.Mode);
                           end;
                           //enqueue branch destinations
                           if node.brtrue  <> 0 then AddrToDo := AddrToDo + [node.brtrue];
                           Add_I(new_instr,FListaIstr,lDeleteLast);

                           lstOpPred.Add(new_instr.ToString(True));

                           Continue
                      end;
                      Add_I(FDisAsm.Insn,FListaIstr,lDeleteLast);
                  end;
                  //
                  //
                  if (not FDisAsm.IsCall)  and (not FDisAsm.IsRet)  then
                  begin
                      //set the branch destinations
                      node.brtrue := FDisAsm.BranchDestination;
                      //unconditional jumps dont have a brfalse
                      if(FDisAsm.Id <> Ord(X86_INS_JMP)) and (FDisAsm.Id <> Ord(X86_INS_LJMP)) then
                          node.brfalse := ea + FDisAsm.Size;

                      //consider register/memory branches as terminal nodes
                      if(FDisAsm.Insn.operands[0].tipo <> T_IMM) then
                           Continue;

                      //enqueue branch destinations
                      if node.brtrue  <> 0 then AddrToDo := AddrToDo + [node.brtrue];
                      if node.brfalse <> 0 then AddrToDo := AddrToDo + [node.brfalse];

                      Continue
                  end;
             end;
             if FDisAsm.IsCall then
             begin
                 // if FDisAsm.x86.operands[0].op.tipo = Ord(X86_OP_MEM_) then
                 //     node.brtrue := FDisAsm.ResolveOpValue(0)
                 // else
                  //TODO: add this to a queue to be analyzed later
                  node.brtrue  := FDisAsm.BranchDestination;
                  node.brfalse := ea + FDisAsm.Size;

                  if node.brtrue  <> 0 then AddrToDo := AddrToDo + [node.brtrue];
                  if node.brfalse <> 0 then AddrToDo := AddrToDo + [node.brfalse];

                  Continue;
             end;
             //return
             if FDisAsm.IsRet then
             begin
                 Result := Result;
                 Continue;
             end;
             node.Fine := node.Fine + FDisAsm.Size;
             AddrToDo  := AddrToDo + [ea + FDisAsm.Size];
         end;
         Result := FListaIstr;
     finally
       AddrDone.Free;
       lstOpPred.SaveToFile('OpaquePredicateList.txt');
     end;
end;

(*
	Name: IsStopCond
	Description: Controllo se raggiunto opcode di stop
*)
function TCFG_Analysis.IsStopCond(insn : TCpuIstruz):Boolean;
begin

    if (insn.OpCode.Mnem >= Ord(X86_INS_JAE)) and (insn.OpCode.Mnem <= Ord(X86_INS_JS) ) then
       if (insn.OpCode.Mnem <> Ord(X86_INS_JMP)) then
          Exit(True);

    if (insn.OpCode.Mnem = Ord(X86_INS_CALL)) then   Exit(True);
    if (insn.OpCode.Mnem = Ord(X86_INS_RET))  then   Exit(True);

    {if (insn.insn.id = Ord(X86_INS_MOV)) or (insn.insn.id = Ord(X86_INS_MOVABS))then
          if (x86.operands[0].op.Tipo = Ord(X86_OP_REG))  and (x86.operands[1].op.Tipo = Ord(X86_OP_IMM))  then
             Exit(True);}

    Result := False;
end;

function TCFG_Analysis.OpPredicate(ListaIstr: TLinkedList<TCpuIstruz>; jcc_Cmd: Word; var lEsegueSalto: Boolean):Boolean;
var
 emu_list  : TLinkedList<TCpuIstruz>;
 Current   : TLinkedListNode<TCpuIstruz>;
 current_I : TCpuIstruz;
 regs      : Registers;
 Eflags    : UInt64;

begin
    Result        := False ;
    emu_list    := nil;
    lEsegueSalto:= False;
    FEmulator.init_reg_context(regs, STACK_ADDRESS);
    try

       try
         if ListaIstr.Last = nil then Exit(True);

         current_I := ListaIstr.Last.Data;

         // cmp
         if (current_I.Opcode.mnem =  Ord(X86_INS_CMP)) or ( current_I.Opcode.mnem =  Ord(X86_INS_CMPXCHG)) then
           Result := False
         // test
         else if ( current_I.Opcode.mnem =  Ord(X86_INS_TEST) )  then
           Result := False
         // or reg_1,Reg_1
         else if ( current_I.Opcode.mnem = Ord(X86_INS_OR)) and  (current_I.operands[0].Tipo =  T_REG) and
                 ( current_I.operands[0].reg = current_I.operands[1].reg) then
           Result := False
         else if ( current_I.Opcode.mnem = Ord(X86_INS_AND)) and  (current_I.operands[0].Tipo =  T_REG) and
                 ( current_I.operands[1].Tipo = T_IMM) and  ( current_I.operands[1].imm.S <= $80 ) and
                 ( current_I.operands[0].size.U >= 4 )then
           Result := False
         else begin
                   //LoadState(regs);
                   emu_list  := TLinkedList<TCpuIstruz>.Create;
                   Current   := ListaIstr.Last;

                   while (Current <> nil) do
                   begin
                       if not FDisAsm.IsCFI(Current.Data) then
                           emu_list.AddFirst(Current.Data);

                       if IsStopCond(Current.Data) then
                          Break;

                      Current := Current.Prev;
                   end;

                   OutDbg('checking Opaque Predicates Addr: '+ IntToHex(FDisAsm.address));

                   FEmulator.emulate_code(emu_list.first, nil, regs);

                   Eflags := regs.eflags ;

                   if emu_list.Count < 1 then
                     lEsegueSalto := True
                   else
                     lEsegueSalto := FDisAsm.IsBranchGoingToExecute(Mnemonics(jcc_Cmd), Eflags,0 );
                   Result := True;
         end;
       except
        OutDbg('Errore on Opaque Predicate Processing:');
       end;
    finally
       if emu_list <> nil then
            emu_list.Free;
    end;

end;

end.
