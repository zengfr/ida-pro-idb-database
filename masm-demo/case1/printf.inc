wsprintfA    PROTO C :VARARG
wsprintf     equ <wsprintfA>

lstrlenA     PROTO :DWORD
lstrlen      equ <lstrlenA>

GetStdHandle PROTO :DWORD
WriteFile    PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

STD_OUTPUT_HANDLE equ -11
NULL              equ 0
