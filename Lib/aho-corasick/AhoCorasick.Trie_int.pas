{***************************************************************************}
{                                                                           }
{
{                                                                           }
{***************************************************************************}
unit AhoCorasick.Trie_int;

interface

uses
  System.Classes, System.Generics.Collections, System.Generics.Defaults, AhoCorasick.Interval_int;

type
  
  PSuccessNode = ^TSuccessNode;
  TSuccess = TArray<PSuccessNode>;
  TEmits = TArray<TEmit>;
  TState = class(TObject)
  private
    FDepth: Integer;    
    FSuccNum: Integer;
    FSuccess: TSuccess; 
    FFailure: TState;   
    FEmits: TEmits;
  public
    Idx: Integer;
    constructor Create(const ADepth: Integer);
    destructor Destroy; override;
    function AddEmit(const AKeyword: UCS4String; const idx: Integer): TEmit; overload;
    procedure AddEmit(const AEmits: TEmits); overload;
    function GotoLeaf(const AChar: UCS4Char): TState;
    function AddLeaf(const AChar: UCS4Char): TState;
    function IsWordHead: Boolean; inline;         
    procedure QuickSort(const aCompare: IComparer<PSuccessNode>);

    property Success: TSuccess read FSuccess;
    property Failure: TState read FFailure write FFailure;
    property Depth: Integer read FDepth;
    property Emits: TEmits read FEmits; 
  end;

  TSuccessNode = record
    Key  : UCS4Char;
    State: TState;
  end;

  TTrie = class(TObject)
  private
    FFileName: string;        
    FRootState: TState;        
    FEmits: TList<TEmit>;      
    FParses: TList<TEmit>;     
    FTokens: TList<TToken>;    
    FItlTree: TIntervalTree;   
    FFailuresCreated: Boolean; 
    FCaseInsensitive: Boolean; 
    FAllowOverlaps: Boolean;   
    FOnleyWholeWord: Boolean;
    FNumKeyWord: Integer;

    function CreateFragment(aEmit: TEmit; aText: UCS4String; aLastCollectedPos: Integer): TToken;
    function CreateMatch(aEmit: TEmit; aText: UCS4String): TToken;
    procedure RemovePartialMatches(aSearch: UCS4String);
    procedure CreateFailures;
    procedure CheckFailuresCreated;
    procedure ClearParseResult;
    procedure CLearTokenResult;
    procedure StoreEmits(aPos: Integer; aCurrent: TState);
    class function NextState(aCurrent: TState; const AChar: UCS4Char): TState;
    class function GotoNext(aCurrent: TState; const AChar: UCS4Char): TState;
  public
    constructor Create;
    destructor Destroy; override;

    procedure CaseSensitive;
    procedure RemoveOverlaps;
    procedure OnlyWholeWords;

    procedure AddKeyword(const aKey: UCS4String);
    function Tokenize(const aText: UCS4String): TList<TToken>;
    function ParseText(const aText: UCS4String): TList<TEmit>;
    function Filter(aText: UCS4String): UCS4String;
    function HasBlackWord(const aText: UCS4String): Boolean;
    function LoadKeywordsFromFile(const aFileName: string): Boolean;
    function Init(const aFileName: string): Boolean;
    property RootState: TState read FRootState;
  end;

function SuccessNodeCompareOrd(const ALeft, ARight: PSuccessNode): Integer;

implementation

uses
  System.SysUtils, System.StrUtils, System.Character;

var
  U_CompareOrd: IComparer<PSuccessNode>;

function MidUCS4String(const AText: UCS4String; const AStart, ACount: Integer): UCS4String; overload;
begin
    Result := Copy(AText, AStart, ACount);
end;

function IsSkipChar(var AChar: UCS4Char; const aCaseInsensitive: Boolean): Boolean;
begin
  Result := not Char.IsLetterOrDigit(AChar);
  if Result then
    Exit;
  if aCaseInsensitive then
    AChar := Char.ToUpper(AChar);
end;

function SuccessNodeCompareOrd(const ALeft, ARight: PSuccessNode): Integer;
begin
  Result := Word(ALeft^.Key) - Word(ARight^.Key);
end;

{ TState }
constructor TState.Create(const ADepth: Integer);
begin
  inherited Create;

  FSuccNum := 0;
  FDepth := ADepth;
  Failure := nil;
  if FDepth = 0 then
    FFailure := Self;
end;

destructor TState.Destroy;
var
  LP: PSuccessNode;
begin
  for LP in FSuccess do
  begin
    LP.State.Free;
    Dispose(LP);
  end;
  SetLength(FSuccess, 0);
  SetLength(FEmits, 0);
  inherited;
end;

procedure TState.AddEmit(const AEmits: TEmits);
var
  LEmit: TEmit;
begin
  for LEmit in AEmits do
  begin
    SetLength(FEmits, Length(FEmits) + 1);
    FEmits[high(FEmits)] := LEmit;
  end;
end;

function TState.AddEmit(const AKeyword: UCS4String; const idx: Integer): TEmit;
begin
  SetLength(FEmits, Length(FEmits) + 1);
  Result := TEmit.Create(0, Length(AKeyword) - 1, AKeyword,idx);
  FEmits[high(FEmits)] := Result;
end;

function TState.AddLeaf(const AChar: UCS4Char): TState;
var
  LP: PSuccessNode;
begin
  Result := GotoLeaf(AChar);
  if not Assigned(Result) then
  begin
    Result := TState.Create(FDepth + 1);

    New(LP);
    LP^.Key := AChar;
    LP^.State := Result;
    Inc(FSuccNum);
    SetLength(FSuccess, FSuccNum);
    FSuccess[FSuccNum - 1] := LP;

    QuickSort(U_CompareOrd);
  end;
end;

function TState.GotoLeaf(const AChar: UCS4Char): TState;
var
  L, R, C: Integer;
begin
  Result := nil;

  L := 0;
  R := FSuccNum - 1;
  while L <= R do
  begin
    C := (L + R) shr 1;
    if FSuccess[C]^.Key < AChar then
      L := C + 1
    else
    begin
      R := C - 1;
      if FSuccess[C]^.Key = AChar then
        Result := FSuccess[C]^.State;
    end;
  end;
end;

function TState.IsWordHead: Boolean;
begin
  Result := (FDepth = 1);
end;

procedure TState.QuickSort(const aCompare: IComparer<PSuccessNode>);
begin
  TArray.Sort<PSuccessNode>(FSuccess, aCompare);
end;

{ TTrie }
procedure TTrie.CaseSensitive;
begin
  FCaseInsensitive := False;
end;

procedure TTrie.RemoveOverlaps;
begin
  FAllowOverlaps := False;
end;

procedure TTrie.OnlyWholeWords;
begin
  FOnleyWholeWord := True;
end;

constructor TTrie.Create;
begin
  inherited Create;

  FCaseInsensitive := True;
  FAllowOverlaps := True;
  FOnleyWholeWord := False;

  FRootState := TState.Create(0);
  FFailuresCreated := False;

  FEmits := TList<TEmit>.Create;
  FParses := TList<TEmit>.Create;
  FTokens := TList<TToken>.Create;

  FNumKeyWord := 0;
end;

destructor TTrie.Destroy;
var
  I: Integer;
begin
  if Assigned(FRootState) then
    FRootState.Free;

  for I := 0 to FEmits.Count - 1 do
  begin
    FEmits[I].Free;
  end;
  FEmits.Free;

  ClearParseResult;
  FParses.Free;

  CLearTokenResult;
  FTokens.Free;

  inherited;
end;

procedure TTrie.ClearParseResult;
var
  I: Integer;
begin
  if FAllowOverlaps then
  begin
    for I := 0 to FParses.Count - 1 do
      FParses[I].Free;
  end
  else
  begin
    if Assigned(FItlTree) then
      FItlTree.Free;
  end;
  FParses.Clear;
end;

procedure TTrie.CLearTokenResult;
var
  I: Integer;
begin
  for I := 0 to FTokens.Count - 1 do
    FTokens[I].Free;

  FTokens.Clear;
end;

procedure TTrie.AddKeyword(const aKey: UCS4String);
var
  LKey: UCS4String;
  LCurr: TState;
  LChar: UCS4Char;
  LEmit: TEmit;
begin
  if Length(aKey) <= 0 then
    Exit;

  LKey := aKey;
  //if FCaseInsensitive then
    //LKey := UnicodeStringToUCS4String( ToUpper( UCS4StringToUnicodeString(aKey) ) );

  LCurr := FRootState;
  for LChar in LKey do
  begin
    //if not Char.IsLetterOrDigit(LChar) then
     // Continue;

    LCurr := LCurr.AddLeaf(LChar);
  end;
  LEmit := LCurr.AddEmit(aKey,FNumKeyWord);
  Inc(FNumKeyWord);
  FEmits.Add(LEmit);
  FFailuresCreated := False;
end;

procedure TTrie.CheckFailuresCreated;
begin
  if not FFailuresCreated then
    CreateFailures;
end;

procedure TTrie.CreateFailures;
var
  LQueue: TQueue<TState>;
  LCurr, LNext: TState;
  LPreFail, LNextFail: TState;
  LP: PSuccessNode;
begin
  LQueue := TQueue<TState>.Create;
  try
    
    for LP in FRootState.Success do
    begin
      LCurr := LP^.State;
      LCurr.Failure := FRootState;
      LQueue.Enqueue(LCurr);
    end;

    
    while LQueue.Count > 0 do
    begin
      LCurr := LQueue.Dequeue;
      
      for LP in LCurr.Success do
      begin
        LNext := LP^.State;
        LQueue.Enqueue(LNext);

        
        LPreFail := LCurr.Failure;
        while NextState(LPreFail, LP^.Key) = nil do
          LPreFail := LPreFail.Failure;

        LNextFail := NextState(LPreFail, LP^.Key);
        LNext.Failure := LNextFail;
        
        LNext.AddEmit(LNextFail.Emits)
      end;
    end;

    FFailuresCreated := True;
  finally
    LQueue.Free;
  end;
end;

procedure TTrie.StoreEmits(aPos: Integer; aCurrent: TState);
var
  LNew, LOld: TEmit;
begin
  for LOld in aCurrent.Emits do
  begin
    LNew := TEmit.Create(aPos - LOld.Size + 1, aPos, LOld.Keyword,LOld.Index);
    FParses.Add(LNew);
  end;
end;

function TTrie.LoadKeywordsFromFile(const aFileName: string): Boolean;
var
  LLines: TStringList;
  LKey: String;
begin
  Result := False;
  if not FileExists(aFileName) then
    Exit;

  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(aFileName, TEncoding.UTF8);
    for LKey in LLines do
    begin
      AddKeyword( UnicodeStringToUCS4String(Trim(LKey)));
    end;
    Result := True;
  finally
    LLines.Free;
  end;
end;

function TTrie.Init(const aFileName: string): Boolean;
begin
  FFileName := aFileName;
  if LoadKeywordsFromFile(FFileName) then
    CreateFailures;

  Result := FFailuresCreated;
end;

class function TTrie.GotoNext(aCurrent: TState; const AChar: UCS4Char): TState;
begin
  Result := NextState(aCurrent, AChar);
  while Result = nil do
  begin
    aCurrent := aCurrent.Failure;
    Result := NextState(aCurrent, AChar)
  end;
end;

class function TTrie.NextState(aCurrent: TState; const AChar: UCS4Char): TState;
begin
  Result := aCurrent.GotoLeaf(AChar);
  if (Result = nil) and (aCurrent.Depth = 0) then
    Result := aCurrent;
end;

function TTrie.CreateFragment(aEmit: TEmit; aText: UCS4String; aLastCollectedPos: Integer): TToken;
var
  LCount: Integer;
begin

  LCount := Length(aText) + 1;
  if Assigned(aEmit) then
    LCount := aEmit.GetStart;
  Dec(LCount, aLastCollectedPos);
  Result := TFragmentToken.Create(MidUCS4String(aText, aLastCollectedPos, LCount));
end;

function TTrie.CreateMatch(aEmit: TEmit; aText: UCS4String): TToken;
begin
  Result := TMatchToken.Create(MidUCS4String(aText, aEmit.GetStart, aEmit.Size), aEmit);
end;

function TTrie.Tokenize(const aText: UCS4String): TList<TToken>;
var
  LLastCollectedPos: Integer;
  LEmit: TEmit;
begin
  ClearParseResult;
  ParseText(aText);

  LLastCollectedPos := 1;
  for LEmit in FParses do
  begin
    if LEmit.GetStart - LLastCollectedPos > 0 then
      FTokens.Add(CreateFragment(LEmit, aText, LLastCollectedPos));
    FTokens.Add(CreateMatch(LEmit, aText));
    LLastCollectedPos := LEmit.GetEnd + 1;
  end;

  if Length(aText) - LLastCollectedPos > 0 then
    FTokens.Add(CreateFragment(nil, aText, LLastCollectedPos));
  Result := FTokens;
end;

function TTrie.ParseText(const aText: UCS4String): TList<TEmit>;
var
  I: Integer;
  LText: UCS4String;
  LChar: UCS4Char;
  LCurr: TState;

begin
  CheckFailuresCreated;
  ClearParseResult;

  LText := aText;

  I := 0;
  LCurr := FRootState;
  for LChar in LText do
  begin
    Inc(I);

    LCurr := GotoNext(LCurr, LChar);
    StoreEmits(I, LCurr);
  end;

  if FOnleyWholeWord then
    RemovePartialMatches(LText);

  if not FAllowOverlaps then
  begin
    FItlTree := TIntervalTree.Create(TList<TInterval>(FParses));
    FItlTree.RemoveOverlaps(TList<TInterval>(FParses));
  end;

  Result := FParses;
end;

function TTrie.Filter(aText: UCS4String): UCS4String;
var
  I, J, N, LStart: Integer;
  LText: UCS4String;
  LChar: UCS4Char;
  LCurr: TState;
begin
  CheckFailuresCreated;

  LText := aText;
  //if FCaseInsensitive then
  //  LText := UnicodeStringToUCS4String( ToUpper( UCS4StringToUnicodeString(aText) ) );

  N := 0;
  LCurr := FRootState;
  for I := 1 to Length(LText) do
  begin
    Inc(N);
    LChar := LText[I];
    if not Char.IsLetterOrDigit(LChar) then
    begin
      Continue;
    end;
    LCurr := GotoNext(LCurr, LChar);

    if LCurr.IsWordHead then
    begin
      N := 0;
    end;
    if Length(LCurr.Emits) > 0 then
    begin
      LStart := I - N;
      for J := LStart to I do
        aText[J] := ucs4char('*');

      N := 0;
    end;
  end;
  Result := aText;
end;

function TTrie.HasBlackWord(const aText: UCS4String): Boolean;
var
  I: Integer;
  LChar: UCS4Char;
  LCurr: TState;
begin
  Result := False;
  CheckFailuresCreated;

  LCurr := FRootState;
  for I := 1 to Length(aText) do
  begin
    LChar := aText[I];
    if not Char.IsLetterOrDigit(LChar) then
      Continue;

    if FCaseInsensitive then
      LChar := Char.ToUpper(LChar);

    LCurr := GotoNext(LCurr, LChar);
    if Length(LCurr.Emits) > 0 then
    begin
      Exit(True);
    end;
  end;
end;

procedure TTrie.RemovePartialMatches(aSearch: UCS4String);
var
  LSize: Integer;
  I: Integer;
  LEmit: TEmit;
begin
  LSize := Length(aSearch);
  for I := FParses.Count - 1 downto 0 do
  begin
    LEmit := FParses[I];
    if ((LEmit.GetStart = 1) or (not Char(aSearch[LEmit.GetStart - 1]).IsLetterOrDigit)) and
      ((LEmit.GetEnd = LSize) or (not Char(aSearch[LEmit.GetEnd + 1]).IsLetterOrDigit)) then
    begin
      Continue;
    end;

    FParses.Remove(LEmit);
    LEmit.Free;
  end;
end;

initialization
  U_CompareOrd := TComparer<PSuccessNode>.Construct(SuccessNodeCompareOrd);

finalization
  U_CompareOrd := nil;

end.
