{ *************************************************************************** }
{ www.hankcs.com/program/algorithm/implementation-and-analysis-of-aho-corasick-algorithm-in-java.html
  {*************************************************************************** }
unit AhoCorasick.Interval_int;

interface

uses
  System.Classes, System.Generics.Collections;

type
  
  TInterval = class(TObject)
  private
    FStart: Integer; 
    FEnd: Integer;   
  public
    constructor Create(const AStart, AEnd: Integer);

    function Equals(AOther: TObject): Boolean; override;
    function Size: Integer;
    function ToString: string; override;
    function OverlapsWith(const AOther: TInterval): Boolean; overload; 
    function OverlapsWith(const APoint: Integer): Boolean; overload; 
    property GetStart: Integer read FStart;
    property GetEnd: Integer read FEnd;
  end;

  
  TEmit = class(TInterval)
  private
    FKeyword: UCS4String;
    FIndex  : Integer;
  public
    constructor Create(const AStart, AEnd: Integer; const AKeyword: UCS4String; const Idx: Integer);
    function ToString: string; override;
    property Keyword: UCS4String read FKeyword;
    property Index  : Integer    read FIndex;
  end;

  
  TIntervalNode = class(TObject)
  private type
    TDirection = (LEFT, RIGHT);
  private
    FLeft: TIntervalNode;         
    FRight: TIntervalNode;        
    FPoint: Integer;              
    FIntervals: TList<TInterval>; 
    FInited: Boolean;
    procedure Initial; inline;
  protected
    procedure AddToOverlaps(const AItl: TInterval; AOverlaps, ANewOverlaps: TList<TInterval>);
    function CheckForOverlaps(const AItl: TInterval; const ADir: TDirection): TList<TInterval>;
    function CheckForOverlapsToTheLeft(const AItl: TInterval): TList<TInterval>;
    function CheckForOverlapsToTheRight(const AItl: TInterval): TList<TInterval>;
    class function FindOverlappingRanges(const aNode: TIntervalNode; const AItl: TInterval)
      : TList<TInterval>;
  public
    constructor Create(const AItls: TList<TInterval>);
    destructor Destroy; override;
    function CalcMedian(const AItls: TList<TInterval>): Integer; 
    function FindOverlaps(const AItl: TInterval): TList<TInterval>; 
  end;

  
  TIntervalTree = class(TObject)
  private
    FRootNode: TIntervalNode; 
    FOverlapResult: TList<TInterval>;
  public
    constructor Create(const AItls: TList<TInterval>);
    destructor Destroy; override;

    procedure RemoveOverlaps(var AItls: TList<TInterval>); 
    function FindOverlaps(AItl: TInterval): TList<TInterval>; 
  end;

  TToken = class(TObject)
  private
    FFragment: UCS4String;
  public
    constructor Create(const AFragment: UCS4String);
    destructor Destroy; override;

    function IsMatch: Boolean; virtual; abstract;
    function GetEmit: TEmit; virtual; abstract;
    property Fragment: UCS4String read FFragment;
  end;

  TMatchToken = class(TToken)
  private
    FEmit: TEmit;
  public
    constructor Create(const AFragment: UCS4String; const AEmit: TEmit);
    function IsMatch: Boolean; override;
    function GetEmit: TEmit; override;
  end;

  TFragmentToken = class(TToken)
  public
    function IsMatch: Boolean; override;
    function GetEmit: TEmit; override;
  end;

implementation

uses
  System.SysUtils, System.Generics.Defaults, System.Character;

var
  U_CompareSize, U_ComparePos: IComparer<TInterval>;

{ TInterval }
constructor TInterval.Create(const AStart, AEnd: Integer);
begin
  FStart := AStart;
  FEnd := AEnd;
end;

function TInterval.Equals(AOther: TObject): Boolean;
begin
  Result := (FStart = TEmit(AOther).GetStart) and (FEnd = TEmit(AOther).GetEnd)
end;

function TInterval.Size: Integer;
begin
  Result := FEnd - FStart + 1;
end;

function TInterval.ToString: string;
begin
  Result := Format('%d : %d', [FStart, FEnd]);
end;

function TInterval.OverlapsWith(const AOther: TInterval): Boolean;
begin
  Result := (FStart <= AOther.GetEnd) and (FEnd >= AOther.GetStart);
end;

function TInterval.OverlapsWith(const APoint: Integer): Boolean;
begin
  Result := (FStart <= APoint) and (FEnd >= APoint);
end;

function IntervalComparerByPos(const ALeft, ARight: TInterval): Integer;
begin
  Result := ALeft.GetStart - ARight.GetStart;
end;

function IntervalComparerBySize(const ALeft, ARight: TInterval): Integer;
begin
  if ALeft.Size < ARight.Size then
    Result := 1
  else if ALeft.Size > ARight.Size then
    Result := -1
  else
    Result := IntervalComparerByPos(ALeft, ARight);
end;

{ TEmit }
constructor TEmit.Create(const AStart, AEnd: Integer; const AKeyword: UCS4String; const Idx: Integer);
begin
  inherited Create(AStart, AEnd);
  FIndex   := Idx;
  FKeyword := AKeyword;
end;

function TEmit.ToString: string;
begin
  Result := inherited ToString + ' = ' + UCS4StringToUnicodeString(FKeyword);
end;

{ TINode }
constructor TIntervalNode.Create(const AItls: TList<TInterval>);
var
  LItl: TInterval;
  LToLeft, LToRight: TList<TInterval>; 
begin
  if not FInited then
    Initial;

  FPoint := CalcMedian(AItls);

  LToLeft := TList<TInterval>.Create;
  LToRight := TList<TInterval>.Create;
  try
    for LItl in AItls do
    begin
      if LItl.GetEnd < FPoint then
        LToLeft.Add(LItl)
      else if LItl.GetStart > FPoint then
        LToRight.Add(LItl)
      else
        FIntervals.Add(LItl);
    end;

    if LToLeft.Count > 0 then
      FLeft := TIntervalNode.Create(LToLeft);

    if LToRight.Count > 0 then
      FRight := TIntervalNode.Create(LToRight);
  finally
    FreeAndNil(LToLeft);
    FreeAndNil(LToRight);
  end;
end;

destructor TIntervalNode.Destroy;
var
  LItl: TInterval;
begin
  if Assigned(FLeft) then
    FreeAndNil(FLeft);
  if Assigned(FRight) then
    FreeAndNil(FRight);

  for LItl in FIntervals do
  begin
    LItl.Free;
  end;
  FIntervals.Free;
  inherited;
end;

procedure TIntervalNode.Initial;
begin
  inherited Create();

  FLeft := nil;
  FRight := nil;
  FIntervals := TList<TInterval>.Create;
  FInited := True;
end;

function TIntervalNode.CalcMedian(const AItls: TList<TInterval>): Integer;
var
  LItl: TInterval;
  LStart, LEnd: Integer;
begin
  LStart := -1;
  LEnd := -1;

  for LItl in AItls do
  begin
    if (LItl.GetStart < LStart) or (LStart = -1) then
      LStart := LItl.GetStart;
    if (LItl.GetEnd > LEnd) or (LEnd = -1) then
      LEnd := LItl.GetEnd;
  end;

  Result := (LStart + LEnd) shr 1;
end;

procedure TIntervalNode.AddToOverlaps(const AItl: TInterval; AOverlaps, ANewOverlaps: TList<TInterval>);
var
  LItl: TInterval;
begin
  if not Assigned(ANewOverlaps) then
    Exit;

  try
    for LItl in ANewOverlaps do
    begin
      if not LItl.Equals(AItl) then
        AOverlaps.Add(LItl);
    end;
  finally
    if ANewOverlaps <> FIntervals then
      ANewOverlaps.Free;
  end;
end;

function TIntervalNode.CheckForOverlaps(const AItl: TInterval; const ADir: TDirection) : TList<TInterval>;
var
  LItl: TInterval;
begin
  Result := TList<TInterval>.Create;
  for LItl in FIntervals do
  begin
    case ADir of
      TDirection.LEFT:
        if LItl.GetStart <= AItl.GetEnd then
          Result.Add(LItl);
      TDirection.RIGHT:
        if LItl.GetEnd >= AItl.GetStart then
          Result.Add(LItl);
    end;
  end;
end;


function TIntervalNode.CheckForOverlapsToTheLeft(const AItl: TInterval): TList<TInterval>;
begin
  Result := CheckForOverlaps(AItl, TDirection.LEFT);
end;


function TIntervalNode.CheckForOverlapsToTheRight(const AItl: TInterval): TList<TInterval>;
begin
  Result := CheckForOverlaps(AItl, TDirection.RIGHT);
end;

class function TIntervalNode.FindOverlappingRanges(const aNode: TIntervalNode; const AItl: TInterval): TList<TInterval>;
begin
  if Assigned(aNode) then
    Result := aNode.FindOverlaps(AItl)
  else
    Result := nil;
end;

function TIntervalNode.FindOverlaps(const AItl: TInterval): TList<TInterval>;
begin
  Result := TList<TInterval>.Create;

  if not Assigned(AItl) then
    Exit;

  if FPoint < AItl.GetStart then
  begin 
    AddToOverlaps(AItl, Result, FindOverlappingRanges(FRight, AItl));
    AddToOverlaps(AItl, Result, CheckForOverlapsToTheRight(AItl));
  end
  else if FPoint > AItl.GetEnd then
  begin 
    AddToOverlaps(AItl, Result, FindOverlappingRanges(FLeft, AItl));
    AddToOverlaps(AItl, Result, CheckForOverlapsToTheLeft(AItl));
  end
  else
  begin 
    AddToOverlaps(AItl, Result, FIntervals);
    AddToOverlaps(AItl, Result, FindOverlappingRanges(FLeft, AItl));
    AddToOverlaps(AItl, Result, FindOverlappingRanges(FRight, AItl));
  end;
end;

{ TIntervalTree }

constructor TIntervalTree.Create(const AItls: TList<TInterval>);
begin
  inherited Create;
  FRootNode := TIntervalNode.Create(AItls);
end;

destructor TIntervalTree.Destroy;
begin
  if Assigned(FRootNode) then
    FreeAndNil(FRootNode);

  if Assigned(FOverlapResult) then
    FreeAndNil(FOverlapResult);

  inherited;
end;

function TIntervalTree.FindOverlaps(AItl: TInterval): TList<TInterval>;
begin
  if Assigned(FOverlapResult) then
    FOverlapResult.Free;
  FOverlapResult := FRootNode.FindOverlaps(AItl);

  Result := FOverlapResult;
end;

procedure TIntervalTree.RemoveOverlaps(var AItls: TList<TInterval>);
var
  LRemoveItls: TList<TInterval>;
  LItl: TInterval;
begin
  
  AItls.Sort(U_CompareSize);

  LRemoveItls := TList<TInterval>.Create;
  try
    for LItl in AItls do
    begin

      if LRemoveItls.Contains(LItl) then
        Continue;

      
      LRemoveItls.AddRange(FindOverlaps(LItl));
    end;

    
    for LItl in LRemoveItls do
    begin
      AItls.Remove(LItl);
    end;
  finally
    LRemoveItls.Free;
  end;

  
  AItls.Sort(U_ComparePos);
end;

{ TToken }

constructor TToken.Create(const AFragment: UCS4String);
begin
  inherited Create;
  FFragment := AFragment;
end;

destructor TToken.Destroy;
begin
  inherited;
end;

{ TMatchToken }
constructor TMatchToken.Create(const AFragment: UCS4String; const AEmit: TEmit);
begin
  inherited Create(AFragment);
  FEmit := AEmit;
end;

function TMatchToken.GetEmit: TEmit;
begin
  Result := FEmit;
end;

function TMatchToken.IsMatch: Boolean;
begin
  Result := True;
end;

{ TFragmentToken }
function TFragmentToken.GetEmit: TEmit;
begin
  Result := nil;
end;

function TFragmentToken.IsMatch: Boolean;
begin
  Result := False;
end;

initialization
  U_CompareSize := TComparer<TInterval>.Construct(IntervalComparerBySize);
  U_ComparePos := TComparer<TInterval>.Construct(IntervalComparerByPos);

finalization
  U_CompareSize := nil;
  U_ComparePos := nil;

end.
