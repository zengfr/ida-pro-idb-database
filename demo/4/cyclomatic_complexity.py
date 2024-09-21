#!/usr/bin/python

from idc import *
from idaapi import *
from idautils import *
from sets import Set

def cyclomatic_complexity(function_ea):
  """
  Cyclomatic Complexity function - by Ero Carrera  

  Calculate the cyclomatic complexity measure for a function.
  Given the starting address of a function, it will find all the basic block's boundaries and edges
  between them and will return the cyclomatic complexity, defined as:
    CC = Edges - Nodes + 2
  """

  f_start = function_ea
  f_end = FindFuncEnd(function_ea)
  edges = Set()
  boundaries = Set((f_start,))

  for head in Heads(f_start, f_end):
    if isCode(GetFlags(head)):
      refs = CodeRefsFrom(head, 0)
      refs = Set(filter(lambda x: x>=f_start and x<=f_end, refs))
      
      if refs:
        next_head = NextHead(head, f_end)
        if isFlow(GetFlags(next_head)):
          refs.add(next_head)
        boundaries.union_update(refs)

        for r in refs:
          if isFlow(GetFlags(r)):
            edges.add((PrevHead(r, f_start), r))
          edges.add((head, r))

  return len(edges) - len(boundaries) + 2

class CyclomaticComplexityChoose(Choose2):
  def __init__(self, title):
    Choose2.__init__(self, title, [ 
        ["Address", 8 | Choose2.CHCOL_HEX], 
        ["Name", 30 | Choose2.CHCOL_PLAIN], 
        ["Complexity", 6 | Choose2.CHCOL_DEC],
        ["Library func", 6 | Choose2.CHCOL_PLAIN] ])

    self.title  = title
    self.colors = (0xF3E2A9, 0xCEF6E3, 0xFA2ECC, 0xFFFF)
    self.items  = []
    self.icon   = 41
    self.PopulateItems()

  def OnClose(self):
    return True

  def OnSelectLine(self, n):
    item = self.items[int(n)]
    jumpto(int(item[0], 16))

  def OnGetLine(self, index):
    return self.items[index]

  def OnGetSize(self):
    return len(self.items)

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnGetLineAttr(self,n):
    complexity = int(self.items[n][2])
    color = self.colors[0]
    if 10 < complexity <= 20:
      color = self.colors[1]
    elif 20 < complexity <= 50:
      color = self.colors[2]
    elif complexity > 50:
      color = self.colors[3]
    return [color, 0]

  def OnRefresh(self, n):
    return n

  def OnCommand(self, n, cmd_id):
    if cmd_id == self.cmd_exc_lib_funcs:
      self.exclude_lib_funcs()
    return n

  def exclude_lib_funcs(self):
    if not len(self.items):
      return False 
    self.items = [i for i in self.items if i[3] != 'True']
    return True

  def show(self):
    n_functions = len(list(Functions()))
    if n_functions > 0:      
      b = self.Show()
      if b == 0:
        self.cmd_exc_lib_funcs = self.AddCommand("Exclude library functions")
        return True
    else:
      warning("IDA has not identified functions.")
      return False

  def PopulateItems(self):
    for function_ea in Functions():
      self.items.append([
        "%08x" % function_ea, 
        GetFunctionName(function_ea), 
        "%d" % cyclomatic_complexity(function_ea),
        "%s" % ((GetFunctionFlags(function_ea) & FUNC_LIB) != 0)
      ])

def show_choose():
  choose = CyclomaticComplexityChoose("Cyclomatic complexity")
  choose.show()

class CyclomaticComplexity_t(plugin_t):
  flags = PLUGIN_UNL
  comment = "Cyclomatic Complexity"
  help = ""
  wanted_name = "Cyclomatic Complexity"
  wanted_hotkey = ""

  def init(self):
    self.icon_id = 0
    return PLUGIN_OK

  def run(self, arg=0):
    show_choose()

  def term(self):
    pass

def PLUGIN_ENTRY():
  return CyclomaticComplexity_t()

if __name__ == '__main__':
  show_choose()
  
