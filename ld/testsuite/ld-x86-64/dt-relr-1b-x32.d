#source: dt-relr-1.s
#as: --x32
#ld: -shared -melf32_x86_64 $DT_RELR_LDFLAGS -z nocombreloc -z nomark-plt
#readelf: -r -s --wide
#target: x86_64-*-linux*

Relocation section '.rela.bar' at offset 0x[0-9a-f]+ contains 1 entry:
 +Offset +Info +Type +Sym. Value +Symbol's Name \+ Addend
[0-9a-f]+ +[0-9a-f]+ +R_X86_64_32 +0+ +data1 \+ 0

Relocation section '.rela.foo' at offset 0x[0-9a-f]+ contains 1 entry:
 +Offset +Info +Type +Sym. Value +Symbol's Name \+ Addend
[0-9a-f]+ +[0-9a-f]+ +R_X86_64_32 +0+ +data1 \+ 0

Relocation section '.rela.plt' at offset 0x[0-9a-f]+ contains 1 entry:
 +Offset +Info +Type +Sym. Value +Symbol's Name \+ Addend
[0-9a-f]+ +[0-9a-f]+ +R_X86_64_JUMP_SLOT +0+ +func1 \+ 0

Relocation section '.relr.dyn' at offset 0x[a-f0-9]+ contains 2 entries:
#...
0000: +[0-9a-f]+ [0-9a-f]+ +.* \(new starting address\)
0001: +[0-9a-f]+ [0-9a-f]+ +.* \(start of bitmap\)
 +[0-9a-f]+ +.*
#...
Symbol table '.symtab' contains [0-9]+ entries:
 +Num: +Value +Size Type +Bind +Vis +Ndx Name
#...
 +[0-9]+: +[a-f0-9]+ +0 +NOTYPE +LOCAL +DEFAULT +[0-9]+ +__ehdr_start
#pass
