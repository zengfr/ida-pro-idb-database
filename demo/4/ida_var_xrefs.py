import ida_struct
import idc
import ida_frame
import ida_hexrays
import idaapi
def get_function_vars(function) -> list:
    frameId = idc.get_frame_id(function)
    if frameId:
        varStruct = ida_struct.get_struc(frameId)
        if varStruct:
            return [mem for mem in varStruct.members]
    return []
def get_variable_refs(function, mem) -> ida_frame.xreflist_t():
    xrefs = ida_frame.xreflist_t()
    ida_frame.build_stkvar_xrefs(xrefs, function, mem)
    return [xref.ea for xref in xrefs]
def get_hexrays_vars(ea) -> dict:
    hexrays_types = {}
    try:
        decompiled = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return {}
    if not decompiled:
        return {}
    for var in decompiled.get_lvars():
        print(var.name)
def test():
  for var in ins.vars_read:
      depd = [(func.mlil[i].address, ins.address) 
              for i in func.mlil.get_var_definitions(var) 
              if func.mlil[i].address != ins.address]
  for var in ins.vars_written:
      depd += [(ins.address, func.mlil[i].address)
              for i in func.mlil.get_var_uses(var)
              if func.mlil[i].address != ins.address]
cur_addr = idaapi.get_screen_ea()
pfn = idaapi.get_func(cur_addr)
mems=get_function_vars(pfn)
for mem in mems:
  xrefs=get_variable_refs(pfn,mem)
  for xref in xrefs:
    name=ida_struct.get_member_name(mem.id)
    fullname=ida_struct.get_member_fullname(mem.id)
    print('%-16s %-1s %03x %03x %03x %8s %08x | %-16s'%(name,"",mem.soff,mem.eoff,mem.eoff-mem.soff,mem.props,xref,idc.GetDisasm(xref)))