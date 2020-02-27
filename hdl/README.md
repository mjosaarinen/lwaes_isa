# HDL for the AES / SM4 instruction 

2020-01-29  Markku-Juhani O. Saarinen <mjos@pqshield.com>

The main instruction is in [enc1s.v](enc1s.v), while [sboxes.v](sboxes.v) has 
s-box implementations for AES (forward and reverse) and SM4.
The thing is 100 lines + sboxes. Perhaps timing can be improved with a 
better implementation, but this one is pretty compact as can be seen.

I've tested this into our Pluto RV32 core as a Custom0 (encoded as an r-type in 
an obvious way, with fn going into funct7), wrote wrappers for inline assembly
and ran the test code first in a simulator, and then on FPGA. It seems to work 
fine. (Our SoC also has a hardware AES module, can run against it too.)

A note about [sboxes.v](sboxes.v): I created linear SM4 "top" and "bottom" 
layers for the Boyar-Peralta AES S-Box to demonstrate the fact that all 
three s-box types can share circuitry. That file has some commentary on this.

However, I didn't mux it as the mux logic would be relatively large. 
Of course, all of that is irrelevant for FPGAs where it's probably a table 
anyway -- the purpose was just wanted to demonstrate the relationship 
between the S-Boxes.

There's a super-simplistic [Makefile](Makefile) and a testbench for Icarus 
Verilog (which is freely available for Debian/Ubuntu etc). I have also tried 
this on Xilinx xsim and vivado with the C language test suite (the same
one as in the parent).

##	Testing

No output from `make test` implies that output matches with 
[tbref.txt](tbref.txt). More test output can be generated using the C
emulator code (in parent directory); the same testbench output can be 
generated with `./xtest tb`; just modify the ` test_hwtb()` function
in [../main.c](../main.c) to generate more test cases.

```console
$ make
iverilog -o sim.vvp enc1s_tb.v sboxes.v enc1s.v
vvp -N sim.vvp
[TB] rd=a56363c6 rs1=00000000 rs2=00000000 fn=00
[TB] rd=6e6edcb2 rs1=00000000 rs2=01234567 fn=01
[TB] rd=5ab4ee5a rs1=00000000 rs2=02468ace fn=02
[TB] rd=f68d7b7b rs1=00000000 rs2=0369d035 fn=03
[TB] rd=000000de rs1=00000000 rs2=048d159c fn=04
[TB] rd=00003900 rs1=00000000 rs2=05b05b03 fn=05
[TB] rd=00660000 rs1=00000000 rs2=06d3a06a fn=06
[TB] rd=c5000000 rs1=00000000 rs2=07f6e5d1 fn=07
[TB] rd=0728ebb2 rs1=00000000 rs2=091a2b38 fn=08
[TB] rd=670a0cb1 rs1=00000000 rs2=0a3d709f fn=09
[TB] rd=7ca1470a rs1=00000000 rs2=0b60b606 fn=0a
[TB] rd=4ffcd7e5 rs1=00000000 rs2=0c83fb6d fn=0b
[TB] rd=00000019 rs1=00000000 rs2=0da740d4 fn=0c
[TB] rd=0000dc00 rs1=00000000 rs2=0eca863b fn=0d
[TB] rd=00530000 rs1=00000000 rs2=0fedcba2 fn=0e
[TB] rd=e3000000 rs1=00000000 rs2=11111109 fn=0f
[TB] rd=5353d784 rs1=00000000 rs2=12345670 fn=10
[TB] rd=c030f0c0 rs1=00000000 rs2=13579bd7 fn=11
[TB] rd=020a0808 rs1=00000000 rs2=147ae13e fn=12
[TB] rd=46fafabc rs1=00000000 rs2=159e26a5 fn=13
[TB] rd=00051428 rs1=00000000 rs2=16c16c0c fn=14
[TB] rd=9b6ddb60 rs1=00000000 rs2=17e4b173 fn=15
[TB] rd=5bb7e096 rs1=00000000 rs2=1907f6da fn=16
[TB] rd=13608209 rs1=00000000 rs2=1a2b3c41 fn=17

$ make test
vvp -n sim.vvp | grep "[TB]" | diff - tbref.txt
$
```

##	Gate Counts

There's a [Yosys](http://www.clifford.at/yosys/) script to perform gate
counts against a mock ASIC cell library. Running `make rep` will perform
synthesis and report counts on four targets:

| **Target**           | **Gates** | **Transistors** | **LTP** |
|:--------------------:|:-------:|:------:|:---:|
| AES, Encrypt only    |  644.0  |  2576  |  24 |
| AES                  | 1215.0  |  4860  |  29 |
| SM4                  |  757.0  |  3028  |  27 |
| AES + SM4 (Full)     | 1629.5  |  6518  |  29 |

LTP is the reported *Longest Topological Path* and essentially a circuit
depth / gate delay measure.

Cheers,
- markku

