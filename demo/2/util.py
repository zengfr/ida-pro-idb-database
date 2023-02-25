
来源 网络 未知
https://github.com/zengfr/ida-pro-idb-database/tree/main/demo/2
from enum import Enum
import bisect, copy, heapq, importlib, sys, itertools, time, os, functools, struct, re
import re


def register_name_to_size(reg):
    if reg in ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"]:
        return 8
    elif reg in ["ax", "bx", "cx", "dx", "di", "si", "bp", "sp"]:
        return 16
    elif reg in ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]:
        return 32
    elif reg in ["x87"]:
        return 80
    else:
        return -1


def to_hex(s):
    return "".join("{:02x}".format(ord(c)) for c in s)


def to_hex_spaced(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)


def hex_to_bin(s):
    s = s[2:] if s.startswith("0x") else s
    return ''.join([chr(int(x, 16)) for x in hex_split(s)])


def hex_split(s):
    return [s[k:k+2] for k in xrange(0, len(s), 2)]


def to_addr(s):  # raise ValueError if the conversion fail
    s = s.replace(" ", "")
    if s.endswith("L"):
        s = s[:-1]
    if not re.match('^[0-9a-fA-F]+$', s if not s.startswith("0x") else s[2:]):
        raise ValueError
    return int(s, 16) if s.startswith("0x") else int(s)


def nsplit(s, n):  # Split a list into sublists of size "n"
    return [s[k:k+n] for k in xrange(0, len(s), n)]

def align_up(v, a=16384):
    return (v + a - 1) & ~(a - 1)

align = align_up

def align_down(v, a=16384):
    return v & ~(a - 1)

def hexdump(s, sep=" "):
    return sep.join(["%02x"%x for x in s])

def hexdump32(s, sep=" "):
    vals = struct.unpack("<%dI" % (len(s)//4), s)
    return sep.join(["%08x"%x for x in vals])

def _ascii(s):
    s2 = ""
    for c in s:
        if c < 0x20 or c > 0x7e:
            s2 += "."
        else:
            s2 += chr(c)
    return s2

def chexdump(s, st=0, abbreviate=True, indent="", print_fn=print):
    last = None
    skip = False
    for i in range(0,len(s),16):
        val = s[i:i+16]
        if val == last and abbreviate:
            if not skip:
                print_fn(indent+"%08x  *" % (i + st))
                skip = True
        else:
            print_fn(indent+"%08x  %s  %s  |%s|" % (
                  i + st,
                  hexdump(val[:8], ' ').ljust(23),
                  hexdump(val[8:], ' ').ljust(23),
                  _ascii(val).ljust(16)))
            last = val
            skip = False

_extascii_table_low = [
    "▪", "☺", "☻", "♥", "♦", "♣", "♠", "•",
    "◘", "○", "◙", "♂", "♀", "♪", "♫", "☼",
    "►", "◄", "↕", "‼", "¶", "§", "▬", "↨",
    "↑", "↓", "→", "←", "∟", "↔", "▲", "▼"]

_extascii_table_high = [
    "⌂",
    "█", "⡀", "⢀", "⣀", "⠠", "⡠", "⢠", "⣠",
    "⠄", "⡄", "⢄", "⣄", "⠤", "⡤", "⢤", "⣤",
    "⠁", "⡁", "⢁", "⣁", "⠡", "⡡", "⢡", "⣡",
    "⠅", "⡅", "⢅", "⣅", "⠥", "⡥", "⢥", "⣥",
    "⠃", "⡃", "⢃", "⣃", "⠣", "⡣", "⢣", "⣣",
    "⠇", "⡇", "⢇", "⣇", "⠧", "⡧", "⢧", "⣧",
    "⠉", "⡉", "⢉", "⣉", "⠩", "⡩", "⢩", "⣩",
    "⠍", "⡍", "⢍", "⣍", "⠭", "⡭", "⢭", "⣭",
    "⠊", "⡊", "⢊", "⣊", "⠪", "⡪", "⢪", "⣪",
    "⠎", "⡎", "⢎", "⣎", "⠮", "⡮", "⢮", "⣮",
    "⠑", "⡑", "⢑", "⣑", "⠱", "⡱", "⢱", "⣱",
    "⠕", "⡕", "⢕", "⣕", "⠵", "⡵", "⢵", "⣵",
    "⠚", "⡚", "⢚", "⣚", "⠺", "⡺", "⢺", "⣺",
    "⠞", "⡞", "⢞", "⣞", "⠾", "⡾", "⢾", "⣾",
    "⠛", "⡛", "⢛", "⣛", "⠻", "⡻", "⢻", "⣻",
    "⠟", "⡟", "⢟", "⣟", "⠿", "⡿", "⢿", "⣿"]

def _extascii(s):
    s2 = ""
    for c in s:
        if c < 0x20:
            s2 += _extascii_table_low[c]
        elif c > 0x7e:
            s2 += _extascii_table_high[c-0x7f]
        else:
            s2 += chr(c)
    return s2

def ehexdump(s, st=0, abbreviate=True, indent="", print_fn=print):
    last = None
    skip = False
    for i in range(0,len(s),16):
        val = s[i:i+16]
        if val == last and abbreviate:
            if not skip:
                print_fn(indent+"%08x  *" % (i + st))
                skip = True
        else:
            print_fn(indent+"%08x  %s  %s  |%s|" % (
                  i + st,
                  hexdump(val[:8], ' ').ljust(23),
                  hexdump(val[8:], ' ').ljust(23),
                  _extascii(val).ljust(16)))
            last = val
            skip = False

def chexdump32(s, st=0, abbreviate=True):
    last = None
    skip = False
    for i in range(0,len(s),32):
        val = s[i:i+32]
        if val == last and abbreviate:
            if not skip:
                print("%08x  *" % (i + st))
                skip = True
        else:
            print("%08x  %s" % (
                i + st,
                hexdump32(val, ' ')))
            last = val
            skip = False

def unhex(s):
    s = re.sub(r"/\*.*?\*/", "", s)
