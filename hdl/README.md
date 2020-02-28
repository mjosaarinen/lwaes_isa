# HDL for the AES / SM4 instruction 

2020-01-29  Markku-Juhani O. Saarinen <mjos@pqshield.com>

2020-02-28	Updated with gate counts.

The main instruction is in [enc1s.v](enc1s.v), while [sboxes.v](sboxes.v)
has S-box implementations for AES and SM4. As can be seen, the entire thing
is only about 100 lines + sboxes. Timing can be significantly further 
improved. 

If your design doesn't need both AES and SM4, or you just need the forward
AES, you can use macros `E1S_NO_AES`, `E1S_NO_AESI`, or `E1S_NO_SM4` to 
disable forward AES, inverse AES, or SM4 respectively.

A note about [sboxes.v](sboxes.v): I created linear SM4 "top" and "bottom" 
layers for the [Boyar-Peralta](https://eprint.iacr.org/2011/332.pdf) AES
S-Box to demonstrate the fact that all three s-box types can share circuitry.
The [sboxes.v](sboxes.v) file has some commentary on this.

Currently the code does not mux the middle layer, which would reduce gate
count. Also note that the the 21->8 bit bottom layers (which are linear) 
can be merged ("collapsed into") the 8->32 bit output layers since they are 
also linear. This would reduce timing and possibly gate count too. The
present code prioritizes readability over these considerations.

There's a simple [Makefile](Makefile) and a testbench for Icarus 
Verilog (which is freely available for Debian/Ubuntu etc). 

I have also tested this on Xilinx xsim and vivado with the C and Assembler
language test suites (see parent directory). PQShield's Pluto RV32 core 
(on an Artix-7 FPGA) was used, although build files are not provided for
that.


##	CMOS Area and Latency Estimate

There's a [Yosys](http://www.clifford.at/yosys/) script to make area
estimates against a mock CMOS ASIC cell library. Running `make rep` will
perform synthesis and report gate and transistor counts on four separate
"feature sets" of the instruction:

| **Target**           | **Gate Equivalents** | **Transistors** | **LTP** |
|----------------------|--------:|-------:|----:|
| AES Encrypt (only)   |  642.0  |  2568  |  25 |
| AES                  | 1240.0  |  4960  |  28 |
| SM4                  |  766.5  |  3066  |  25 |
| AES + SM4 (full)     | 1678.5  |  6714  |  28 |

LTP is the reported *Longest Topological Path* and essentially a circuit
depth / gate delay measure.

Currently the weights are such that transistors = 4*GE, but this can be
tuned in the [yoparse.py] script.

Yosys version used: 
`Yosys 0.9+1706 (git sha1 cd60f079, clang 6.0.0-1ubuntu2 -fPIC -Os)`


##	Testing with a Simulator

No output from `make test` implies that output matches with 
[tbref.txt](tbref.txt). More test outpust can be generated using the 
C emulator code (in parent directory); the same testbench output can be 
generated with `./xtest tb`; just modify the ` test_hwtb()` function in 
[../main.c](../main.c) to generate more test cases.

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

Icarus Verilog verions:
`Icarus Verilog Parser/Elaborator version 11.0 (devel) (s20150603-796-g875431a3)`
`Icarus Verilog runtime version 11.0 (devel) (s20150603-796-g875431a3)`

Cheers,
- markku

