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
