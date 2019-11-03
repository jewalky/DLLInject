# DLLInject
Static DLL injection tool.

Appends a custom loader at the end of an executable, with a custom import table.
Features:
- can import multiple libraries with a single config
- can import both by ordinal and name

Possible issues:
- result PE may be detected as esoteric heuristic malware due to loader being present

## Example use
https://github.com/jewalky/a2mgr_rom2me/blob/master/postbuild/rom2me.dis
