```
masm汇编使用调用c函数方法invoke伪指令printf带参数格式化
printf函数在汇编中实现
masm_asm_use_call_c_func_invoke_printf_format.md
-----------------------------printf.inc
wsprintfA    PROTO C :VARARG
wsprintf     equ <wsprintfA>

lstrlenA     PROTO :DWORD
lstrlen      equ <lstrlenA>

GetStdHandle PROTO :DWORD
WriteFile    PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

STD_OUTPUT_HANDLE equ -11
NULL              equ 0
-------------------------------printf.asm
.386
.model flat,stdcall
option casemap:none

include     printf.inc

.data?

buffer      db 512 dup(?)
_esi        dd ?

.code

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

printf PROC C _format:DWORD,args:VARARG

    mov     _esi,esi
    mov     esi,DWORD PTR [esp]
    mov     DWORD PTR [esp],OFFSET buffer
    call    wsprintf

    invoke  lstrlen,ADDR buffer

    push    NULL
    mov     ecx,esp
    push    NULL
    push    ecx     ; ecx -> lpNumberOfBytesWritten
    push    eax    
    push    OFFSET buffer
    
    invoke  GetStdHandle,STD_OUTPUT_HANDLE
    push    eax
    call    WriteFile
    mov     eax,DWORD PTR [esp]
    pop     ecx

    mov     DWORD PTR [esp],esi
    mov     esi,_esi

    IFDEF   __POASM__

        retn

    ELSE

        ret

    ENDIF

printf ENDP

OPTION PROLOGUE:PROLOGUEDEF
OPTION EPILOGUE:EPILOGUEDEF

END
----------------------------test.inc
.386
.model flat,stdcall
option casemap:none

ExitProcess PROTO :DWORD

includelib  kernel32.lib
includelib  user32.lib
----------------------------test.asm
include     Test.inc

printf      PROTO C _format:DWORD,args:VARARG

.data

f1          db 'editor:zengfr %s %s',0
str1        db 'This is',0
str2        db 'a test.',0

.code

start:

    invoke  printf,ADDR f1,ADDR str1,ADDR str2
    invoke  ExitProcess,0

END start

完整代码 https://github.com/zengfr/ida-pro-idb-database/masm-demo/case1/
masm_asm_use_call_c_func_invoke_printf_format.md
--------------------------------------ml link cmd编译build.bat
\masm32\bin\ml /c /coff printf.asm
\masm32\bin\ml /c /coff Test.asm
\masm32\bin\polink /SUBSYSTEM:CONSOLE /LIBPATH:\masm32\lib\ /OUT:Test.exe Test.obj printf.obj
@echo demo code:https://github.com/zengfr/ida-pro-idb-database/masm-demo/case1/
@echo masm_asm_use_call_c_func_invoke_printf_format.md
pause
----------------------------------------------------------------------
case2 再送一个Windows Win32位平台 MASM汇编.386
printf函数在汇编中实现
.model flat,stdcall
option casemap:none

include C:\masm32\include\windows.inc
include C:\masm32\include\kernel32.inc

includelib C:\masm32\lib\kernel32.lib

.data
    hellotext db "Hello World",0
    dwCharWrite dd 0

.code

START:
    invoke GetStdHandle,STD_OUTPUT_HANDLE
    invoke WriteConsole,eax,offset hellotext,sizeof hellotext,offset dwCharWrite,NULL
end START


