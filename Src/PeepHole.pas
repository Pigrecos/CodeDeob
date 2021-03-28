unit PeepHole;

interface
   uses System.SysUtils, windows ,System.Classes, System.Generics.Collections,
        ACTypes,ACStato,ACPattern,Assemble,
        CapstoneX86,AhoCorasick.Interval_int,AhoCorasick.Trie_int;

type
  TValidPredicate  = Reference to function(const Res  : TEmit): Boolean;
  TBetterPredicate = Reference to function(const a, b : TEmit): Boolean;

 TPeepHole = class
   private
     FPatterns  : TArray<TPattern>;
     FTrie      : TTrie;
     FModo      : Byte;   //32 or 64
     FJSonPath  : string;
     function  preprocessIn(vIn: TArray<TIstruzione>): UCS4String;
     procedure preprocessTrie;
     procedure Clear;
     procedure MakeMultiOp(const aMnem : TMultiOp; const Aistruz, ARepl: TArray<TIstruzione>; const pat : ACPattern.TPattern);
     procedure SetMode(const Value: Byte);
   public
     constructor Create(vPatterns : TArray<TPattern>);overload;
     constructor Create(PathJSon: string = ''); overload;
     function  prettyPrint(keyword : UCS4String): String;
     function  ApplyPeepHole(vIn: TArray<TIstruzione>; var vOut : TArray<TIstruzione>; var FEmits: TList<TEmit>): Boolean;
     function  LoadFromJson(jsonFile: string): Boolean;

     property  Patterns : TArray<TPattern>  read FPatterns;
     property  Modo     : Byte              read FModo     write SetMode;
     property  JSonPath : string            read FJSonPath write FJSonPath;
 end;

implementation
         uses Convert,superobject;
{ TPeepHole }

constructor TPeepHole.Create(vPatterns: TArray<TPattern>);
begin
    FPatterns := vPatterns;
    FModo     := 32;

    FTrie     := TTrie.Create;
    preprocessTrie;
end;

constructor TPeepHole.Create(PathJSon: string = '');
begin
    FJSonPath := PathJSon ;

    SetLength(FPatterns,0);
    FModo := 32;
    FTrie := TTrie.Create;

end;

Procedure TPeepHole.Clear;
begin
    SetLength(FPatterns,0);
    FTrie.Free;

    FTrie := TTrie.Create;
end;

procedure TPeepHole.MakeMultiOp(const aMnem : TMultiOp; const Aistruz, ARepl: TArray<TIstruzione>; const pat : ACPattern.TPattern);
var
  j,i,x,y: Integer;
  pPat : ACPattern.TPattern;
begin

    for i := 0 to High(aMnem.OpCodes) do
    begin
        pPat.Clear;
        pPat.priority := Pat.priority;
        pPat.flag     := Pat.flag;
        pPat.Nome     := Pat.Nome;

        for y := 0 to Length(Aistruz) - 1 do
          pPat.Add( Aistruz[y] ) ;

        for y := 0 to Length(ARepl) - 1 do
          pPat.replsIns := pPat.replsIns + [ Arepl[y] ];

        for j := 0 to Length(pPat.instrs) - 1 do
        begin
            if pPat.instrs[j].opcode.mnem = 0 then
            begin
                for x := 0 to Length(pPat.replsIns) - 1 do
                begin
                     if pPat.replsIns[x].opcode.mnem = aMnem.nOp then Break;
                end;

                pPat.instrs[j].opcode.mnem   := aMnem.OpCodes[i];
                pPat.replsIns[x].opcode.mnem := aMnem.OpCodes[i];

                FPatterns := FPatterns + [ pPat ];
            end;
        end;
    end;
end;

function TPeepHole.LoadFromJson(jsonFile: string): Boolean;
var
  JO,
  PatJO   : ISuperObject;
  i,j     : Integer;
  pat     : ACPattern.TPattern;
  istruz  : TIstruzione;
  Aistruz,
  ARepl   : TArray<TIstruzione>;
  sStato  : TStato;
  aMnem   : TMultiOp;
begin
    if not FileExists(jsonFile) then
       raise Exception.Create('File not exists ' + sLineBreak + jsonFile);

    JO := TSuperObject.ParseFile(jsonFile,False);
    if JO = nil then
     raise Exception.Create('Can not load '+jsonFile+',Please delete this file and update it!');

    Clear;
    // carica ricorsivamente tutti i patters
    for i := 0 to JO.A['Patters'].Length - 1 do
    begin
         PatJO := JO.A['Patters'].O[i];
         pat.Clear;
         SetLength(aMnem.OpCodes,0);
         aMnem.nOp := 0;
         sStato.Clear;

         pat.priority := PatJO.I['priority'];
         pat.flag     := StrToIntDef('$'+PatJO.S['Option'],0);
         pat.Nome     := PatJO.S['NomePat'];

         // carica tutte le istruzioni del patter
         Aistruz := istruz.LoadFromJson(PatJO.A['instrs'],sStato,aMnem) ;
         for j := 0 to Length(Aistruz) - 1 do
             pat.Add( Aistruz[j] ) ;

         // carica tutte le nuove istruzioni che sost. il pattern
         SetLength(Arepl,0);
         Arepl := istruz.LoadFromJson(PatJO.A['repls'],sStato,aMnem,True) ;
         for j := 0 to Length(Arepl) - 1 do
            pat.replsIns := pat.replsIns + [ Arepl[j] ];

         // Multi opCodes
         if aMnem.nOp > 0 then  MakeMultiOp(aMnem,Aistruz,Arepl,pat)
         else                   FPatterns := FPatterns + [ pat ] ;
    end;

    preprocessTrie;
    Result := True;
end;

function TPeepHole.ApplyPeepHole(vIn: TArray<TIstruzione>; var vOut : TArray<TIstruzione>; var FEmits: TList<TEmit>): Boolean;
var
  LEmits          : TList<TEmit>;
  Emit            : TEmit;
  pattern         : TPattern;
  product         : TArray<TIstruzione>;
  i,y,LenDelItem  : Integer;
  best            : TDictionary<Integer,Integer>;
  validPredicate  : TValidPredicate;
  BetterPredicate : TBetterPredicate;
  nDeleteItem,
  updIndex        : Integer;
  {$IFDEF  TESTING}tmpLst  : TArray<TIstruzione>; {$ENDIF}

begin
    Result := False;

    if Length(vIn) = 0 then  Exit(False);

    // apply Aho-Corasick algo
    LEmits := FTrie.ParseText( preprocessIn(vIn));
    FEmits := LEmits;

    //no patterns found = not optimized
    if LEmits.Count = 0 then
    begin
        vOut := vIn;
        Exit(False);
    end;

    {$IFDEF  TESTING}
    tmpLst := [];
    for i:= 0 to  High(vIn) do
     tmpLst := tmpLst + [ vIn[i] ];
    {$ENDIF}

    // funzione validazione Patters
    validPredicate := function (const Res  : TEmit): Boolean  //is r a valid result?
    begin
        // Emit.GetStart l'indice inizia da 1 non da 0 -aggiornare
        Result := FPatterns[Res.Index].Match(vIn, Res.GetStart-1);
    end;

    // funzione per verificare la maggiore corrispondenza
    betterPredicate := function (const a, b : TEmit): Boolean //is a better than b?
    var
      pa,pb : TPattern;
    begin

        pa := FPatterns[a.Index];
        pb := FPatterns[b.Index];

        { TODO -oMax -c : Sistemare priorità casi particolari(esp/rsp) 10/08/2018 15:18:32 }
        if pa.priority <> pb.priority then
        begin
            if pa.priority = 251 then Exit(True);
            if pb.priority = 251 then Exit(false);

            if pa.priority = 250 then Exit(True);
            if pb.priority = 250 then Exit(false)
        end;

        if a.size <> b.size then                     Exit (a.size > b.size);
        if a.GetStart <> b.GetStart then             Exit (a.GetStart < b.GetStart);
        if pa.priority <> pb.priority then           Exit (pa.priority > pb.priority);

        Exit(False);
    end;

    best := TDictionary<Integer,Integer>.Create;
    try
      for i:= 0 to LEmits.Count - 1 do
      begin
          Emit := LEmits[i];
          if not validPredicate(Emit) then  Continue;

          if not best.ContainsKey(Emit.GetStart) then
             best.Add(Emit.GetStart,i)
           else if (BetterPredicate(Emit,FEmits[ best[Emit.GetStart] ])) then
             best[Emit.GetStart] := i;
      end;

      i := 0;
      nDeleteItem := 0;
      while i <  Length(vOut) do
      begin
          try
            updIndex := nDeleteItem + i;
            // Emit.GetStart l'indice inizia da 1 non da 0 -aggiornare
            if best.ContainsKey(updIndex + 1) then
            begin
                Result := True;

                Emit := FEmits[ best[updIndex + 1] ];
                pattern := FPatterns[ Emit.Index ];
                { --fp00000014-- salto un ciclo per evitare cercare di risolvere alcuni conflitti con pattern   }
                if (pattern.priority <= 2) and (pattern.priority > 0) then
                begin
                     FPatterns[ Emit.Index ].priority := FPatterns[ Emit.Index ].priority - 1;
                     inc(i);
                     Continue;
                end;

                // match to get the correct state
                pattern.Match(vOut, i);
                if pattern.Produce(product,vOut,i,FModo) then
                begin
                    for y := 0  to High(product) do
                        vOut[i + y] := product[y] ;
                end;

                // remove reference
                LenDelItem := Length(pattern.instrs) - Length(product);
                for y := 0  to LenDelItem - 1 do
                begin
                    inc(nDeleteItem) ;
                    DeleteRef(vOut,(i + Length(product)),FModo);
                    Delete   (vOut,(i + Length(product)),1);
                end;

                i := i + Length(product);
                product := [];

            end else
            begin
                inc(i);
            end;
          except
            raise Exception.Create('Error Processing Istruz n°:'+IntToStr(i));
          end;
      end;
    finally
      best.Free
    end;

end;

function TPeepHole.preprocessIn(vIn: TArray<TIstruzione>): UCS4String;
var
  i    : Integer;
  text : UCS4String;

begin

    SetLength(text,0);
    for i := 0 to Length(vIn) - 1 do
    begin
        if vIn[i].opcode.mnem <> Ord(X86_INS_INVALID) then
          text := text  + [ vIn[i].opcode.mnem ]
    end;

    Result := text;
end;

procedure TPeepHole.preprocessTrie;
var
  keyword : UCS4String;
  instr   : TIstruzione;
  pattern : ACPattern.TPattern;

begin
    
    for pattern in FPatterns do
    begin
        SetLength(keyword,0);
        for instr in pattern.instrs do
        begin
             if instr.opcode.mnem <> Ord(X86_INS_INVALID) then
               keyword := keyword + [instr.opcode.mnem]
        end;
        FTrie.AddKeyword(keyword);
    end;

end;

function TPeepHole.prettyPrint(keyword: UCS4String): String;
var
  mnem : Mnemonics;
begin
    Result := '';
    for mnem in keyword do
    begin
        if Result <> '' then
            Result := Result + ';';
        Result := Result + gConvert.ins2str(mnem);
    end;

end;

procedure TPeepHole.SetMode(const Value: Byte);
begin
    FModo := Value;
    if FJSonPath <> '' then  FJSonPath := FJSonPath + '\';

    if FModo = 64  then  LoadFromJson (FJSonPath + 'Patters_x64.json')
    else                 LoadFromJson (FJSonPath +'Patters_x86.json')
end;

end.
