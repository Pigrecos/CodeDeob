unit Emulation;

interface
    uses SysUtils, System.Classes,Winapi.Windows,
         Unicorn, UnicornConst, X86Const,Collections.LinkedList,CapstoneApi,
         Capstone;

type
  THookMemInvalid= function(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: integer; value: Int64; user_data: Pointer): Boolean of object; cdecl;

  PRegisters = ^Registers;
  Registers  = record
    rax   : UInt64;
    rbx   : UInt64;
    rcx   : UInt64;
    rdx   : UInt64;
    rsp   : UInt64;
    rbp   : UInt64;
    rsi   : UInt64;
    rdi   : UInt64;
    r8    : UInt64;
    r9    : UInt64;
    r10   : UInt64;
    r11   : UInt64;
    r12   : UInt64;
    r13   : UInt64;
    r14   : UInt64;
    r15   : UInt64;
    eflags: UInt64;
    rip   : UInt64;
  end;

  // Helpers to create a callback function out of a object method
  ICallbackStub = interface(IInterface)
    function GetStubPointer: Pointer;
    property StubPointer : Pointer read GetStubPointer;
  end;

  TCallbackStub = class(TInterfacedObject, ICallbackStub)
    private
      fStubPointer : Pointer;
      fCodeSize : integer;
      function GetStubPointer: Pointer;
    public
      constructor Create(Obj : TObject; MethodPtr: Pointer; NumArgs : integer);
      destructor Destroy; override;
  end;

  TEmulation = class(TPersistent)
    private
        FlstMsgDbg     : TStringList;
        FIsLogDbg      : Boolean;
        FModo          : Byte;
        FHookMemInvalid: THookMemInvalid;
        FStubHMemInvali: ICallbackStub;
        function  align_addr(addr: UInt64; mode: UInt8): UInt64;
        function  Hook_Mem_Invalid(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: Integer; value: Int64; user_data: Pointer): Boolean; cdecl;

        function  random_reg_value: UInt64;
        procedure DoLog(FMsg: String);
    public
        constructor Create(Modo: Word);
        destructor  Destroy;override;
        procedure   emulate_code(start, _end: TLinkedListNode<TCpuIstruz>; var regs: Registers);
        procedure   init_reg_context(var regs: Registers; stack_address: UInt64);

        property  DbgMsg   : TStringList read FlstMsgDbg;
        property  Modo     : Byte        read FModo;
        property  IsLogDbg : Boolean     read FIsLogDbg    write FIsLogDbg ;
  end;

 {$INCLUDE Define.inc};

implementation

{ TCallBackStub }

  // Helpers to create a callback function out of a object method
{ ----------------------------------------------------------------------------- }
{ This is a piece of magic by Jeroen Mineur.  Allows a class method to be used  }
{ as a callback. Create a stub using CreateStub with the instance of the object }
{ the callback should call as the first parameter and the method as the second  }
{ parameter, ie @TForm1.MyCallback or declare a type of object for the callback }
{ method and then use a variable of that type and set the variable to the       }
{ method and pass it:                                                           }
{ 64-bit code by Andrey Gruzdev                                                 }
{                                                                               }
{ type                                                                          }
{   TEnumWindowsFunc = function (AHandle: hWnd; Param: lParam): BOOL of object; stdcall; }
{                                                                               }
{  TForm1 = class(TForm)                                                        }
{  private                                                                      }
{    function EnumWindowsProc(AHandle: hWnd; Param: lParam): BOOL; stdcall;     }
{  end;                                                                         }
{                                                                               }
{  var                                                                          }
{    MyFunc: TEnumWindowsFunc;                                                  }
{    Stub: ICallbackStub;                                                       }
{  begin                                                                        }
{    MyFunct := EnumWindowsProc;                                                }
{    Stub := TCallBackStub.Create(Self, MyFunct, 2);                            }
{     ....                                                                      }
{     ....                                                                      }
{  Now Stub.StubPointer can be passed as the callback pointer to any windows API}
{  The Stub will be automatically disposed when the interface variable goes out }
{  of scope                                                                     }
{ ----------------------------------------------------------------------------- }
{$IFNDEF CPUX64}
const
  AsmPopEDX   = $5A;
  AsmMovEAX   = $B8;
  AsmPushEAX  = $50;
  AsmPushEDX  = $52;
  AsmNOP      = $90;
  AsmJmpShort = $E9;
  AsmCall     = $E8;
  AsmAddESP   = $C483;
  ASMMovEDX   = $1589;
  AsmRet      = $C3;
  AsmImmPush  = $68;

type
  TStub = packed record
    PopEDX      : Byte;
    MovEAX      : Byte;
    SelfPointer : Pointer;
    PushEAX     : Byte;
    PushEDX     : Byte;
    MovEDX      : Word;    // for cdecl
    OffSetPush  : Cardinal;
    JmpShort    : Byte;
    Displacement: Integer;
    AddESP      : word;     // for cdecl
    Imm         : Byte;     // for cdecl
    PushImm     : Byte;     // for cdecl
    ImmPush     : Cardinal; // for cdecl
    Ret         : Byte;     // for cdecl

  end;
{$ENDIF CPUX64}

constructor TCallBackStub.Create(Obj: TObject; MethodPtr: Pointer;
  NumArgs: integer);
{$IFNDEF CPUX64}
var
  Stub: ^TStub;
begin
  // Allocate memory for the stub
  // 1/10/04 Support for 64 bit, executable code must be in virtual space
  Stub := VirtualAlloc(nil, SizeOf(TStub), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  // Pop the return address off the stack
  Stub^.PopEDX := AsmPopEDX;

  // Push the object pointer on the stack
  Stub^.MovEAX := AsmMovEAX;
  Stub^.SelfPointer := Obj;
  Stub^.PushEAX := AsmPushEAX;

  // Push the return address back on the stack
  Stub^.PushEDX := AsmNOP;//AsmPushEDX;
  Stub^.MovEDX  := ASMMovEDX;
  Stub^.OffSetPush := Integer(@(Stub^.ImmPush)) ;

  // Jump to the 'real' procedure, the method.
  Stub^.JmpShort := AsmCall ;//AsmJmpShort;
  Stub^.Displacement := (Integer(MethodPtr) - Integer(@(Stub^.JmpShort))) -
    (SizeOf(Stub^.JmpShort) + SizeOf(Stub^.Displacement));

  Stub^.AddESP := AsmAddESP;
  Stub^.Imm    := $4;
  Stub^.PushImm:= AsmImmPush;
  Stub^.Ret    := AsmRet;

  // Return a pointer to the stub
  fCodeSize := SizeOf(TStub);
  fStubPointer := Stub;
{$ELSE CPUX64}
const
RegParamCount = 4;
ShadowParamCount = 4;

Size32Bit = 4;
Size64Bit = 8;

ShadowStack   = ShadowParamCount * Size64Bit;
SkipParamCount = RegParamCount - ShadowParamCount;

StackSrsOffset = 3;
c64stack: array[0..14] of byte = (
$48, $81, $ec, 00, 00, 00, 00,//     sub rsp,$0
$4c, $89, $8c, $24, ShadowStack, 00, 00, 00//     mov [rsp+$20],r9
);

CopySrcOffset=4;
CopyDstOffset=4;
c64copy: array[0..15] of byte = (
$4c, $8b, $8c, $24,  00, 00, 00, 00,//     mov r9,[rsp+0]
$4c, $89, $8c, $24, 00, 00, 00, 00//     mov [rsp+0],r9
);

RegMethodOffset = 10;
RegSelfOffset = 11;
c64regs: array[0..28] of byte = (
$4d, $89, $c1,      //   mov r9,r8
$49, $89, $d0,      //   mov r8,rdx
$48, $89, $ca,      //   mov rdx,rcx
$48, $b9, 00, 00, 00, 00, 00, 00, 00, 00, // mov rcx, Obj
$48, $b8, 00, 00, 00, 00, 00, 00, 00, 00 // mov rax, MethodPtr
);

c64jump: array[0..2] of byte = (
$48, $ff, $e0  // jump rax
);

CallOffset = 6;
c64call: array[0..10] of byte = (
$48, $ff, $d0,    //    call rax
$48, $81,$c4,  00, 00, 00, 00,   //     add rsp,$0
$c3// ret
);
var
  i: Integer;
  P,PP,Q: PByte;
  lCount : integer;
  lSize : integer;
  lOffset : integer;
begin
    lCount := SizeOf(c64regs);
    if NumArgs>=RegParamCount then
       Inc(lCount,sizeof(c64stack)+(NumArgs-RegParamCount)*sizeof(c64copy)+sizeof(c64call))
    else
       Inc(lCount,sizeof(c64jump));

    Q := VirtualAlloc(nil, lCount, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    P := Q;

    lSize := 0;
    if NumArgs>=RegParamCount then
    begin
        lSize := ( 1+ ((NumArgs + 1 - SkipParamCount) div 2) * 2 )* Size64Bit;   // 16 byte stack align

        pp := p;
        move(c64stack,P^,SizeOf(c64stack));
        Inc(P,StackSrsOffset);
        move(lSize,P^,Size32Bit);
        p := pp;
        Inc(P,SizeOf(c64stack));
        for I := 0 to NumArgs - RegParamCount -1 do
        begin
            pp := p;
            move(c64copy,P^,SizeOf(c64copy));
            Inc(P,CopySrcOffset);
            lOffset := lSize + (i+ShadowParamCount+1)*Size64Bit;
            move(lOffset,P^,Size32Bit);
            Inc(P,CopyDstOffset+Size32Bit);
            lOffset := (i+ShadowParamCount+1)*Size64Bit;
            move(lOffset,P^,Size32Bit);
            p := pp;
            Inc(P,SizeOf(c64copy));
        end;
    end;

    pp := p;
    move(c64regs,P^,SizeOf(c64regs));
    Inc(P,RegSelfOffset);
    move(Obj,P^,SizeOf(Obj));
    Inc(P,RegMethodOffset);
    move(MethodPtr,P^,SizeOf(MethodPtr));
    p := pp;
    Inc(P,SizeOf(c64regs));

    if NumArgs<RegParamCount then
      move(c64jump,P^,SizeOf(c64jump))
    else
    begin
      move(c64call,P^,SizeOf(c64call));
      Inc(P,CallOffset);
      move(lSize,P^,Size32Bit);
    end;
    fCodeSize := lcount;
   fStubPointer := Q;
{$ENDIF CPUX64}
end;

destructor TCallBackStub.Destroy;
begin
  VirtualFree(fStubPointer, fCodeSize, MEM_DECOMMIT);
  inherited;
end;

function TCallBackStub.GetStubPointer: Pointer;
begin
  Result := fStubPointer;
end;

constructor TEmulation.Create(Modo: Word);
begin

     FlstMsgDbg := TStringList.Create;
     FIsLogDbg  := False;

     FlstMsgDbg     := TStringList.Create;
     FModo          := Modo;

     FHookMemInvalid := Hook_Mem_Invalid;
     FStubHMemInvali:= TCallbackStub.Create(Self,@FHookMemInvalid,6);
end;

destructor TEmulation.Destroy;
begin
    FlstMsgDbg.Free;
    inherited;

end;

procedure TEmulation.DoLog(FMsg: String);
begin
     if FIsLogDbg then
        FlstMsgDbg.Add(FMsg);
end;


function TEmulation.align_addr(addr: UInt64; mode: UInt8): UInt64;
begin
    case mode of
      CS_MODE_32: addr := addr and $FFFFF000;
      CS_MODE_64: addr := addr and $FFFFFFFFFFFFF000;
    end;
    Result := addr;
end;

function TEmulation.Hook_Mem_Invalid(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: Integer; value: Int64; user_data: Pointer): Boolean; cdecl;
var
  err : uc_err;
begin
 	 address := align_addr(address, FModo);

    case  _type of
        UC_MEM_READ_UNMAPPED:begin
                                // map this memory in with 4kb in size
                                err := uc_mem_map(uc, address, $1000, UC_PROT_ALL);
                                if err <> UC_ERR_OK  then  DoLog(Format('[+] Error mapping new READ memory: %s', [uc_strerror(err)]));
                                // return true to indicate we want to continue
                                Exit(True);
                             end;
       UC_MEM_WRITE_UNMAPPED:begin
                                // map this memory in with 4kb in size
                                err := uc_mem_map(uc, address, $1000, UC_PROT_ALL);
                                if err <> UC_ERR_OK  then  DoLog(Format('[+] Error mapping new WRITE memory: %s', [uc_strerror(err)]));
                                // return true to indicate we want to continue
                                Exit(true);
                             end;
           UC_MEM_FETCH_PROT:begin
                                // map this memory in with 2MB in size
                                uc_mem_map(uc, address, 2 * 1024*1024, UC_PROT_ALL);
                                // return true to indicate we want to continue
                                Exit(true);
                             end;
           UC_MEM_WRITE_PROT:begin
                                // map this memory in with 2MB in size
                                uc_mem_map(uc, address, 2 * 1024*1024, UC_PROT_ALL);
                                // return true to indicate we want to continue
                                Exit(true);
                             end;
            UC_MEM_READ_PROT:begin
                                // map this memory in with 2MB in size
                                uc_mem_map(uc, address, 2 * 1024*1024, UC_PROT_ALL);
                                // return true to indicate we want to continue
                                Exit(true);
                             end
    else
        // map this memory in with 2MB in size
        uc_mem_map(uc, address, 2 * 1024*1024, UC_PROT_ALL);
        // return true to indicate we want to continue
        Exit(true);
    end;
end;

function TEmulation.random_reg_value: UInt64;
var
 num : UInt64;
begin
	num := Random(MaxInt);
	num := (num shl 32 or Random(MaxInt));
	num := (num mod (999999999 - 100000000)) + 100000000;
	result := num;
end;

procedure TEmulation.init_reg_context(var regs:Registers; stack_address: UInt64);
Begin
    ZeroMemory(@regs,SizeOf(Registers));

    regs.rax := random_reg_value();
    regs.rbx := random_reg_value();
    regs.rcx := random_reg_value();
    regs.rdx := random_reg_value();
    regs.rbp := random_reg_value();
    regs.rsp := stack_address + (stack_address div 2);
    regs.rsi := random_reg_value();
    regs.rdi := random_reg_value();

    if(FModo = CS_MODE_64) then
    begin
      regs.r8 := random_reg_value();
      regs.r9 := random_reg_value();
      regs.r10 := random_reg_value();
      regs.r11 := random_reg_value();
      regs.r12 := random_reg_value();
      regs.r13 := random_reg_value();
      regs.r14 := random_reg_value();
      regs.r15 := random_reg_value();
    end;
end;

procedure TEmulation.emulate_code(start, _end: TLinkedListNode<TCpuIstruz>; var regs: Registers);
var
  assembly_size,
  index,esp     : UInt64;
  current       : TLinkedListNode<TCpuIstruz>;
  instruction   : TCpuIstruz;
  assembly      : TArray<Byte>;
  uc            : uc_engine;
  err           : uc_err;
  hook_id_2     : uc_hook;
Begin

    if start = nil then Exit;
    FlstMsgDbg.Clear;

    //generate the byte array to be emulated
    assembly_size := 0;
    current := start;
    while(current <> nil) and (current <> _end) do
    begin
        instruction   := current.Data;
        assembly_size := assembly_size + instruction.size;
        current       := current.next;
    end;

    SetLength(assembly,assembly_size);
    current := start;
    index   := 0;
    while(current <> nil) and (current <> _end) do
    begin
        instruction := current.Data;
        CopyMemory(@assembly[index],@instruction.bytes,instruction.size);
        index   := index + instruction.size;
        current := current.next;
    end;

    err := uc_open(UC_ARCH_X86, FModo, uc);
    if(err <> UC_ERR_OK) then
       raise exception.Create(Format('[-] Error: uc_open, %s', [uc_strerror(err)]));

    err := uc_mem_map(uc, TEXT_ADDRESS, EMU_SIZE, UC_PROT_ALL);
    if(err <> UC_ERR_OK) then
       raise exception.Create(Format('[-] Error: uc_mem_map, %s', [uc_strerror(err)]));

    err := uc_mem_map(uc, STACK_ADDRESS, EMU_SIZE, UC_PROT_ALL);
    if(err <> UC_ERR_OK) then
       raise exception.Create(Format('[-] Error: uc_mem_map, %s', [uc_strerror(err)]));

    err := uc_mem_write_(uc, TEXT_ADDRESS, @assembly[0], assembly_size);
    if(err <> UC_ERR_OK) then
       raise exception.Create(Format('[-] Error: uc_mem_write, %s', [uc_strerror(err)]));

    hook_id_2 := 0;
    uc_hook_add(uc, hook_id_2, UC_HOOK_MEM_INVALID, FStubHMemInvali.StubPointer, nil, UInt64(1), UInt64(0));

    case FModo of
        CS_MODE_32:begin
                      uc_reg_write(uc, UC_X86_REG_EAX, @(regs.rax));
                      uc_reg_write(uc, UC_X86_REG_EBX, @(regs.rbx));
                      uc_reg_write(uc, UC_X86_REG_ECX, @(regs.rcx));
                      uc_reg_write(uc, UC_X86_REG_EDX, @(regs.rdx));
                      uc_reg_write(uc, UC_X86_REG_ESP, @(regs.rsp));
                      uc_reg_write(uc, UC_X86_REG_EBP, @(regs.rbp));
                      uc_reg_write(uc, UC_X86_REG_ESI, @(regs.rsi));
                      uc_reg_write(uc, UC_X86_REG_EDI, @(regs.rdi));
                      uc_reg_write(uc, UC_X86_REG_EFLAGS, @(regs.eflags));
        end;
        CS_MODE_64:begin
                      uc_reg_write(uc, UC_X86_REG_RAX, @(regs.rax));
                      uc_reg_write(uc, UC_X86_REG_RBX, @(regs.rbx));
                      uc_reg_write(uc, UC_X86_REG_RCX, @(regs.rcx));
                      uc_reg_write(uc, UC_X86_REG_RDX, @(regs.rdx));
                      uc_reg_write(uc, UC_X86_REG_RSP, @(regs.rsp));
                      uc_reg_write(uc, UC_X86_REG_RBP, @(regs.rbp));
                      uc_reg_write(uc, UC_X86_REG_RSI, @(regs.rsi));
                      uc_reg_write(uc, UC_X86_REG_RDI, @(regs.rdi));
                      uc_reg_write(uc, UC_X86_REG_R8, @(regs.r8));
                      uc_reg_write(uc, UC_X86_REG_R9, @(regs.r9));
                      uc_reg_write(uc, UC_X86_REG_R10, @(regs.r10));
                      uc_reg_write(uc, UC_X86_REG_R11, @(regs.r11));
                      uc_reg_write(uc, UC_X86_REG_R12, @(regs.r12));
                      uc_reg_write(uc, UC_X86_REG_R13, @(regs.r13));
                      uc_reg_write(uc, UC_X86_REG_R14, @(regs.r14));
                      uc_reg_write(uc, UC_X86_REG_R15, @(regs.r15));
                      uc_reg_write(uc, UC_X86_REG_EFLAGS, @(regs.eflags));
        end;
    end;
    //emulate code
    esp := 0;
    uc_reg_read(uc, UC_X86_REG_ESP, @esp);

    err := uc_emu_start(uc, TEXT_ADDRESS, TEXT_ADDRESS + assembly_size, 0, 0);
    if(err <> UC_ERR_OK) and (err <>  UC_ERR_EXCEPTION)then
    begin
        FlstMsgDbg.SaveToFile('Error_Emulazione');
        raise exception.Create(Format('[-] Error: uc_emu_start, %s', [uc_strerror(err)]));
    end;

    //delete hook
    uc_hook_del(uc, hook_id_2);
    //read registers from emulation context
    case FModo of
      CS_MODE_32:begin
                    uc_reg_read(uc, UC_X86_REG_EAX, @(regs.rax));
                    uc_reg_read(uc, UC_X86_REG_EBX, @(regs.rbx));
                    uc_reg_read(uc, UC_X86_REG_ECX, @(regs.rcx));
                    uc_reg_read(uc, UC_X86_REG_EDX, @(regs.rdx));
                    uc_reg_read(uc, UC_X86_REG_ESP, @(regs.rsp));
                    uc_reg_read(uc, UC_X86_REG_EBP, @(regs.rbp));
                    uc_reg_read(uc, UC_X86_REG_ESI, @(regs.rsi));
                    uc_reg_read(uc, UC_X86_REG_EDI, @(regs.rdi));
                    uc_reg_read(uc, UC_X86_REG_EFLAGS, @(regs.eflags));
                 end;
      CS_MODE_64:begin
                    uc_reg_read(uc, UC_X86_REG_RAX, @(regs.rax));
                    uc_reg_read(uc, UC_X86_REG_RBX, @(regs.rbx));
                    uc_reg_read(uc, UC_X86_REG_RCX, @(regs.rcx));
                    uc_reg_read(uc, UC_X86_REG_RDX, @(regs.rdx));
                    uc_reg_read(uc, UC_X86_REG_RSP, @(regs.rsp));
                    uc_reg_read(uc, UC_X86_REG_RBP, @(regs.rbp));
                    uc_reg_read(uc, UC_X86_REG_RSI, @(regs.rsi));
                    uc_reg_read(uc, UC_X86_REG_RDI, @(regs.rdi));
                    uc_reg_read(uc, UC_X86_REG_R8, @(regs.r8));
                    uc_reg_read(uc, UC_X86_REG_R9, @(regs.r9));
                    uc_reg_read(uc, UC_X86_REG_R10, @(regs.r10));
                    uc_reg_read(uc, UC_X86_REG_R11, @(regs.r11));
                    uc_reg_read(uc, UC_X86_REG_R12, @(regs.r12));
                    uc_reg_read(uc, UC_X86_REG_R13, @(regs.r13));
                    uc_reg_read(uc, UC_X86_REG_R14, @(regs.r14));
                    uc_reg_read(uc, UC_X86_REG_R15, @(regs.r15));
                    uc_reg_read(uc, UC_X86_REG_EFLAGS, @(regs.eflags));
                 end;
    end;
    //closing unicorn
    uc_close(uc);
end;

end.
