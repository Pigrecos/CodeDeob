{
  Pascal/Delphi bindings for the UnicornEngine Emulator Engine

  Copyright(c) 2015 Stefan Ascher

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
}

unit Unicorn;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface


const
{$ifdef Linux}
  LIB_FILE = 'unicorn.o';
{$else}
  {$IFDEF CPUX86 }
    LIB_FILE = 'UnicornX32\Unicorn.dll';
   {$ELSE}
    LIB_FILE = 'UnicornX64\Unicorn.dll';
  {$ENDIF}
{$endif}

type
  uc_engine = Pointer;
  uc_hook = UIntPtr;
  uc_arch = Cardinal;
  uc_mode = Cardinal;
  uc_err = Cardinal;
  
type
  // Callback functions
  // Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
  // @address: address where the code is being executed
  // @size: size of machine instruction(s) being executed, or 0 when size is unknown
  // @user_data: user data passed to tracing APIs.
  uc_cb_hookcode_t = procedure(uc: uc_engine; address: UInt64; size: UInt32; user_data: Pointer); cdecl;
  // Callback function for tracing interrupts (for uc_hook_intr())
  // @intno: interrupt number
  // @user_data: user data passed to tracing APIs.
  uc_cb_hookintr_t = procedure(uc: uc_engine; intno: UInt32; user_data: Pointer); cdecl;
  // Callback function for tracing IN instruction of X86
  // @port: port number
  // @size: data size (1/2/4) to be read from this port
  // @user_data: user data passed to tracing APIs.
  uc_cb_insn_in_t = function(uc: uc_engine; port: UInt32; siz: integer; user_data: Pointer): UInt32; cdecl;
  // x86's handler for OUT
  // @port: port number
  // @size: data size (1/2/4) to be written to this port
  // @value: data value to be written to this port
  uc_cb_insn_out_t = procedure(uc: uc_engine; port: UInt32; size: integer; value: UInt32; user_data: Pointer); cdecl;
  
  // All type of memory accesses for UC_HOOK_MEM_*
  uc_mem_type = integer;
  // All type of hooks for uc_hook_add() API.
  uc_hook_type = integer;

  // Callback function for hooking memory (UC_MEM_READ, UC_MEM_WRITE & UC_MEM_FETCH)
  // @type: this memory is being READ, or WRITE
  // @address: address where the code is being executed
  // @size: size of data being read or written
  // @value: value of data being written to memory, or irrelevant if type = READ.
  // @user_data: user data passed to tracing APIs
  uc_cb_hookmem_t = procedure(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: integer; value: Int64; user_data: Pointer); cdecl;
  // Callback function for handling invalid memory access events (UC_MEM_*_UNMAPPED and
  //   UC_MEM_*PROT events)
  // @type: this memory is being READ, or WRITE
  // @address: address where the code is being executed
  // @size: size of data being read or written
  // @value: value of data being written to memory, or irrelevant if type = READ.
  // @user_data: user data passed to tracing APIs
  // @return: return true to continue, or false to stop program (due to invalid memory).
  uc_cb_eventmem_t = function(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: integer; value: Int64; user_data: Pointer): LongBool; cdecl;
  
// Exports
(*
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
     major & minor versions.
     NOTE: This returned value can be compared with version number made
     with macro UC_MAKE_VERSION

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
*)
function uc_version(var major, minor: Cardinal): Cardinal; cdecl external LIB_FILE;
  
(*
 Determine if the given architecture is supported by this library.

 @arch: architecture type (UC_ARCH_* )

 @return True if this library supports the given arch.
*)
function uc_arch_supported(arch: uc_arch): LongBool; cdecl external LIB_FILE;
  
(*
 Create new instance of unicorn engine.

 @arch: architecture type (UC_ARCH_* )
 @mode: hardware mode. This is combined of UC_MODE_*
 @uc: pointer to uc_engine, which will be updated at return time

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_open(arch: uc_arch; mode: uc_mode; var uc: uc_engine): uc_err; cdecl external LIB_FILE;
  
(*
 Close UC instance: MUST do to release the handle when it is not used anymore.
 NOTE: this must be called only when there is no longer usage of Unicorn.
 The reason is the this API releases some cached memory, thus access to any
 Unicorn API after uc_close() might crash your application.
 After this, @uc is invalid, and nolonger usable.

 @uc: pointer to a handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_close(uc: uc_engine): uc_err; cdecl external LIB_FILE;
  
(*
 Report the last error number when some API function fail.
 Like glibc's errno, uc_errno might not retain its old value once accessed.

 @uc: handle returned by uc_open()

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*)
function uc_errno(uc: uc_engine): uc_err; cdecl external LIB_FILE;
  
(*
 Return a string describing given error code.

 @code: error code (see UC_ERR_* above)

 @return: returns a pointer to a string that describes the error code
 passed in the argument @code
*)
function uc_strerror(code: uc_err): PAnsiChar; cdecl external LIB_FILE;
  
(*
 Write to register.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will set to register @regid

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_reg_write(uc: uc_engine; regid: Integer; const value: Pointer): uc_err; cdecl external LIB_FILE;
  
(*
 Read register value.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_reg_read(uc: uc_engine; regid: Integer; value: Pointer): uc_err; cdecl external LIB_FILE;
  
(*
 Write to a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to set.
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_mem_write_(uc: uc_engine; address: UInt64; const bytes: Pointer;
  size: Cardinal): uc_err; cdecl external LIB_FILE name 'uc_mem_write';
    
(*
 Read a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to get.
 @bytes:   pointer to a variable containing data copied from memory.
 @size:   size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_mem_read_(uc: uc_engine; address: UInt64; bytes: Pointer;
  size: Cardinal): uc_err; cdecl external LIB_FILE name 'uc_mem_read';
    
(*
 Emulate machine code in a specific duration of time.

 @uc: handle returned by uc_open()
 @begin: address where emulation starts
 @until: address where emulation stops (i.e when this address is hit)
 @timeout: duration to emulate the code (in microseconds). When this value is 0,
        we will emulate the code in infinite time, until the code is finished.
 @count: the number of instructions to be emulated. When this value is 0,
        we will emulate all the code available, until the code is finished.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_emu_start(uc: uc_engine; _begin, _until: UInt64; timeout: UInt64;
  size: Cardinal): uc_err; cdecl external LIB_FILE;
    
(*
 Stop emulation (which was started by uc_emu_start() API.
 This is typically called from callback functions registered via tracing APIs.
 NOTE: for now, this will stop the execution only after the current block.

 @uc: handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_emu_stop(uc: uc_engine): uc_err; cdecl external LIB_FILE;
  
(*
 Register callback for a hook event.
 The callback will be run when the hook event is hit.

 @uc: handle returned by uc_open()
 @hh: hook handle returned from this registration. To be used in uc_hook_del() API
 @type: hook type
 @callback: callback to be run when instruction is hit
 @user_data: user-defined data. This will be passed to callback function in its
      last argument @user_data
 @...: variable arguments (depending on @type)

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_hook_add_0(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer): uc_err; cdecl external LIB_FILE name 'uc_hook_add';
function uc_hook_add_1(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer; arg1: integer): uc_err; cdecl external LIB_FILE name 'uc_hook_add';
function uc_hook_add_2(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer; arg1, arg2: UInt64): uc_err; cdecl external LIB_FILE name 'uc_hook_add';

function uc_hook_add(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer): uc_err; overload;
function uc_hook_add(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer; arg1: UInt64): uc_err; overload;
function uc_hook_add(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer; arg1, arg2: UInt64): uc_err; overload;

(*
 Unregister (remove) a hook callback.
 This API removes the hook callback registered by uc_hook_add().
 NOTE: this should be called only when you no longer want to trace.
 After this, @hh is invalid, and nolonger usable.

 @uc: handle returned by uc_open()
 @hh: handle returned by uc_hook_add()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_hook_del(uc: uc_engine; hh: uc_hook): uc_err; cdecl external LIB_FILE;
  
(*
 Map memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the new memory region to be mapped in.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_mem_map(uc: uc_engine; address: UInt64; size: Cardinal; perms: UInt32): uc_err; cdecl external LIB_FILE;
  
(*
 Unmap a region of emulation memory.
 This API deletes a memory mapping from the emulation memory space.

 @handle: handle returned by uc_open()
 @address: starting address of the memory region to be unmapped.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the memory region to be modified.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_mem_unmap(uc: uc_engine; address: UInt64; size: Cardinal): uc_err; cdecl external LIB_FILE;
  
(*
 Set memory permissions for emulation memory.
 This API changes permissions on an existing memory region.

 @handle: handle returned by uc_open()
 @address: starting address of the memory region to be modified.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the memory region to be modified.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: New permissions for the mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
function uc_mem_protect(uc: uc_engine; address: UInt64; size: Cardinal; perms: UInt32): uc_err; cdecl external LIB_FILE;
  
implementation

function uc_hook_add(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer): uc_err; overload;
begin
  Result := uc_hook_add_0(uc, hh, _type, callback, user_data);
end;

function uc_hook_add(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer; arg1: UInt64): uc_err; overload;
begin
  Result := uc_hook_add_1(uc, hh, _type, callback, user_data, arg1);
end;

function uc_hook_add(uc: uc_engine; var hh: uc_hook; _type: integer;
  callback: Pointer; user_data: Pointer; arg1, arg2: UInt64): uc_err; overload;
begin
  Result := uc_hook_add_2(uc, hh, _type, callback, user_data, arg1, arg2);
end;

end.