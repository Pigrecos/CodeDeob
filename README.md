# CodeDeob
 Code Deobfuscator x86_32/64

* The goal was to create a tool that could remove virtual machine (VM) based protections from malware
* This plugin enables you to remove some common obfuscations
* Dead code removal 
* Peephole optimization(for PeepHole used algorithm aho-corasick , inizial idea of [mrexodia](https://github.com/mrexodia)  in [InterObfu](https://github.com/x64dbg/InterObfu)
* remove Multibranch Protection(opaque predicates -  **Experimental..**)
* ..More

### TODO List ###
* testing (especially x86_64)
* and Much more

### P.S ###

* Welcome collaborative testing and improvement of source code(Control Flow Optimize very hard).I have little free time.

### Testing ###
  add the path to the project.
  
* Using [Capstone4Delphi](https://github.com/Pigrecos/Capstone4Delphi). 
* Using [D_CodeGen](https://github.com/Pigrecos/D_CodeGen).

## Usage ##
  
  for the rules for peephole written in the json files the explanation of each single option is complex, I leave it to the good will 
  of those who want to understand ... I unfortunately do not have much time. 

  The example. 
  
~~~asm
Input Code:
push 0x2CC918B9
mov qword ptr [rsp], rsi
push 0x76CF60F1
mov rsi, qword ptr [rsp]
add rsp, 08
push r12
mov r12, rsp
add r12, 08
sub r12, 08
xchg qword ptr [rsp], r12
pop rsp
mov qword ptr [rsp], rdi
push rcx
mov ecx, 0x7EFE8D85
mov rdi, rcx
pop rcx
xor rsi, rdi
mov rdi, qword ptr [rsp]
add rsp, 08
push rcx
mov ecx, 0x8C669373
sub esi, ecx
pop rcx
mov r9, rsi
push qword ptr [rsp]
pop rsi
push r11
mov r11, rsp
add r11, 08
add r11, 08
xchg qword ptr [rsp], r11
pop rsp
push rbp
mov rbp, rsp
add rbp, 08
sub rbp, 08
xchg qword ptr [rsp], rbp
pop rsp
sub rsp, 08
mov qword ptr [rsp], rbp
pop qword ptr [rsp]
push rdi
push 0x23564D19
mov qword ptr [rsp], r10
mov r10d, 0x7DDF3DA8
push r14
push r10
pop r14
mov rdi, r14
pop r14
pop r10
xor qword ptr [rsp+0x8], rdi
mov rdi, qword ptr [rsp]
add rsp, 08
pop rcx
push rbx
mov ebx, 0x7DDF3DA8
xor rcx, rbx
pop rbx
push r8
mov r8d, 0x80
add rcx, r8
mov r8, qword ptr [rsp]
sub rsp, 08
mov qword ptr [rsp], rcx
mov rcx, rsp
add rcx, 08
sub rcx, 08
sub rsp, 08
mov qword ptr [rsp], rcx
push qword ptr [rsp+0x8]
pop rcx
pop qword ptr [rsp]
mov rsp, qword ptr [rsp]
mov qword ptr [rsp], r14
push rsp
pop r14
add r14, 08
add r14, 08
push r14
push qword ptr [rsp+0x8]
pop r14
pop qword ptr [rsp]
mov rsp, qword ptr [rsp]
sub dword ptr [rcx], r9d
nop

---- Deobfuscate Code : -------
sub dword ptr [rbp+0x80], 0x7BCB5A01

========================================
Input Code:
push ebp
push esp
pop ebp
add ebp, 04
sub ebp, 02
xor ebp, dword ptr [esp]
xor dword ptr [esp], ebp
xor ebp, dword ptr [esp]
mov esp, dword ptr [esp]
mov word ptr [esp], di
mov word ptr [esp], bp
mov bp, 0x7987
push ax
mov ax, 0x86CB
push cx
mov cx, 0x342D
sub bp, cx
pop cx
add bp, 0x3260
push ax
mov ax, 0x5EA5
add bp, ax
pop ax
add bp, ax
sub bp, 0x5EA5
sub bp, 0x3260
push ax
mov ax, 0x342D
add bp, ax
pop ax
pop ax
and ax, bp
pop bp
nop

---- Deobfuscate Code : -------
and ax, 0x52
~~~

### CREDITS ###

* thanks to [fvrmatteo](https://github.com/fvrmatteo) for all the new ideas and things i learned thanks to him. Great 
* thanks to [mrexodia](https://github.com/mrexodia) for the code and ideas
