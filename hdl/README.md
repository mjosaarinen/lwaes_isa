# HDL for the AES / SM4 instruction 

2020-01-29  Markku-Juhani O. Saarinen <mjos@pqshield.com>

The main instruction is in [enc1s.v](enc1s.v), while [sboxes.v](sboxes.v) has 
s-box implementations for AES (forward and reverse) and SM4.
The thing is 100 lines + sboxes. Perhaps timing can be improved with a 
better implementation, but this one pretty compact as can be seen.

I popped this into our Pluto RV32 core as a Custom0 (encoded as an r-type in 
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

Apologies if you're offended by my verilog style..

Cheers,
- markku

```console
$ make
iverilog -o sim.vvp enc1s_tb.v sboxes.v enc1s.v
vvp -N sim.vvp
[TB] rd=a56363c6 rs1=00000000 rs2=00000000 fn=00
[TB] rd=6e6edcb2 rs1=01234567 rs2=00000000 fn=01
[TB] rd=5ab4ee5a rs1=02468ace rs2=00000000 fn=02
[TB] rd=f68d7b7b rs1=0369d035 rs2=00000000 fn=03
[TB] rd=000000de rs1=048d159c rs2=00000000 fn=04
[TB] rd=00003900 rs1=05b05b03 rs2=00000000 fn=05
[TB] rd=00660000 rs1=06d3a06a rs2=00000000 fn=06
[TB] rd=c5000000 rs1=07f6e5d1 rs2=00000000 fn=07
[TB] rd=0728ebb2 rs1=091a2b38 rs2=00000000 fn=08
[TB] rd=670a0cb1 rs1=0a3d709f rs2=00000000 fn=09
[TB] rd=7ca1470a rs1=0b60b606 rs2=00000000 fn=0a
[TB] rd=4ffcd7e5 rs1=0c83fb6d rs2=00000000 fn=0b
[TB] rd=00000019 rs1=0da740d4 rs2=00000000 fn=0c
[TB] rd=0000dc00 rs1=0eca863b rs2=00000000 fn=0d
[TB] rd=00530000 rs1=0fedcba2 rs2=00000000 fn=0e
[TB] rd=e3000000 rs1=11111109 rs2=00000000 fn=0f
[TB] rd=5353d784 rs1=12345670 rs2=00000000 fn=10
[TB] rd=c030f0c0 rs1=13579bd7 rs2=00000000 fn=11
[TB] rd=020a0808 rs1=147ae13e rs2=00000000 fn=12
[TB] rd=46fafabc rs1=159e26a5 rs2=00000000 fn=13
[TB] rd=00051428 rs1=16c16c0c rs2=00000000 fn=14
[TB] rd=9b6ddb60 rs1=17e4b173 rs2=00000000 fn=15
[TB] rd=5bb7e096 rs1=1907f6da rs2=00000000 fn=16
[TB] rd=13608209 rs1=1a2b3c41 rs2=00000000 fn=17

$ make test
vvp -n sim.vvp | grep "[TB]" | diff - tbref.txt
$
```

No output from `make test` implies that output matches with 
[tbref.txt](tbref.txt).

