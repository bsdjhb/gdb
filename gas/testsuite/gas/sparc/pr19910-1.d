#as: 
#objdump: -dr --prefix-addresses
#name: PR19910 - make sure that U suffix is accepted

.*: +file format .*

Disassembly of section .text:
0x0+000 sethi[ 	]+%hi\(0x4000\), %g1
0x0+004 mov[ 	]+0x40, %g1
0x0+008 mov[ 	]+4, %g1
