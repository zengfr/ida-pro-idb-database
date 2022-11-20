# IDAMetrics-static.py

This repo forked from https://github.com/mxmssh/IDAmetrics, go to check the original README for more information.

What I did is porting `IDAMetrics_static.py` from IDA 5.5.0 (32 bit) to IDA 7.5.200519 (32 bit).

## Bug fix

### `GetInstructionType` function was erroneous, inaccuracy and hard to extend to x86_64.

#### The erroneous result of `GetInstructionType`

The implementation of `GetInstructionType` function was based on string matching which is erroneous and inaccuracy, e.g. the `leave` instruction would be counted as `ASSIGNMENT_INSTRUCTION` just because the `startswith("lea")` of `leave` is apparently `True`:

```python
for assign_instr_mnem in assign_instructions_general:
        if instr_mnem.startswith(assign_instr_mnem):
            return inType.ASSIGNMENT_INSTRUCTION
```

#### The root cause of inaccuracy of `GetInstructionType`

Also, because the string matching need someone manually build a list. There may be omissions from the list.
For example, `setnz` should be included in `assign_instructions_general`.

```python
assign_instructions_general = [
    "mov", "cmov", "xchg", "bswap", "xadd", "ad", "sub", "sbb", "imul", "mul",
    "idiv", "div", "inc", "dec", "neg", "da", "aa", "and", "or", "xor", "not",
    "sar", "shr", "sal", "shl", "shrd", "shld", "ror", "rol", "rcr", "rcl",
    "lod", "sto", "lea"
]
```

#### How to fix

This kind of information should has been gained by IDA during the analyzing.
Using APIs in module `ida_idp` should solve some problems.
