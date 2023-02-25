
\masm32\bin\ml /c /coff printf.asm
\masm32\bin\ml /c /coff Test.asm
\masm32\bin\polink /SUBSYSTEM:CONSOLE /LIBPATH:\masm32\lib\ /OUT:Test.exe Test.obj printf.obj
@echo demo code:https://github.com/zengfr/ida-pro-idb-database/masm-demo/case1/
@echo masm_asm_use_call_c_func_invoke_printf_format.md
pause