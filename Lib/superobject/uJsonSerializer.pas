unit uJsonSerializer;

interface

uses sysutils, classes, generics.collections, superobject, TypInfo;

type
  TJsonSerializer = class
  private
    class var ctx: TSuperRttiContext;
    class constructor Create;
    class destructor Destroy;
  public
    class function Serialize<T>(const obj: T): String;
    class function Deserialize<T>(const Json: string): T;
    class procedure RegisterCustomMarshaller(TypeInfo: PTypeInfo;
      FromJSON: TSerialFromJson; ToJSON: TSerialToJson);
  end;

implementation

{ TJsonSerializer }

class constructor TJsonSerializer.Create;
begin
  ctx := TSuperRttiContext.Create;
end;

class destructor TJsonSerializer.Destroy;
begin
  freeandnil(ctx);
end;

class procedure TJsonSerializer.RegisterCustomMarshaller(TypeInfo: PTypeInfo;
  FromJSON: TSerialFromJson; ToJSON: TSerialToJson);
begin
  ctx.SerialFromJson.Add(TypeInfo, FromJSON);
  ctx.SerialToJson.Add(TypeInfo, ToJSON);
end;

class function TJsonSerializer.Deserialize<T>(const Json: string): T;
begin
  result := ctx.AsType<T>(SO(Json));
end;

class function TJsonSerializer.Serialize<T>(const obj: T): String;
begin
  result := ctx.AsJson(obj).AsJson(true, false);
end;

end.
