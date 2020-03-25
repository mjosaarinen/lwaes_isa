# A Lightweight (RISC-V) ISA Extension for AES and SM4

January 22, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

**Updated** February 17, 2020: flipped rs1 and rs2; rd=rs1 for "compressed".

## Description

A lightweight ISA extension proposal supporting:

* AES (Advanced Encryption Standard) with 128/192/256 - bit secret key,
as defined in [FIPS 197](doc/NIST.FIPS.197.pdf).

* SM4 Chinese Encryption algorithm [GM/T 0002-2012](doc/gmt0002-2012sm4.pdf)
[(english spec)](doc/sm4en.pdf), also defined in GB/T 32907-2016 and ISO/IEC
18033-3:2010/DAmd 2. SM4 has only one key size, 128 bits.

A single instruction, ENC1S is used for encryption, decryption, and key
schedule for both ciphers. For design rationale and some analysis, see the
short report [A Lightweight ISA Extension for AES and SM4](https://arxiv.org/abs/2002.07041) (to appear at SECRISC-V 2020).

A more complex ISA extension may be appropriate for higher-end CPUs. The
primary goal of ENC1S / lweas is to eliminate timing-side vulnerabilities.
Speed-up over pure software table-based implementations is roughly 500 %.


## Software and Hardware Source Code

This directory contains an "emulator" C implementation of the instruction
together with runnable pseudocode for full encryption, decryption, and
key schedule of AES-128/192/256 and SM4-128. These are intended for
instruction counts, test vector generation, and other such evaluation.
Real assembler listings for the same functions (using a seriously hacky
macro instruction encoding) can be found under the [asm](asm) directory.

The assembler and C code use the same AES and SM4 API, specified in
[aes_enc.h](aes_enc.h) (AES-128/192/256 encryption),
[aes_dec.h](aes_dec.h) (AES-128/192/256 decryption) and
[sm4_encdec.h](sm4_encdec.h) (SM4-128 encryption and decryption).
The API is split in pieces since AES and SM4 are independent of
each other and some designers may additionally want to save space by not
implementing inverse AES (not required for decryption in GCM and many 
other modes).

The [hdl](hdl) directory contains Verilog combinatorial logic for the core
instruction. Simulator and basic CMOS gate count synthesis scripts are
provided for Icarus Verilog and Yosys open source tools. The same assembler
and HDL have been additionally tested with PQShield's proprietary RISC-V
emulator and the "Pluto" core on a live FPGA target, although source
code for those is not provided here.


## Technical Details

The instruction is encapsulated in a single emulator function in
[enc1s.c](enc1s.c):
```C
uint32_t enc1s(uint32_t rs1, uint32_t rs2, int fn);
```
The file [hdl/enc1s.v](hdl/enc1s.v) contains Verilog combinatorial
logic for the instruction that can be used in a RISC-V core.
```verilog
module enc1s(
    output  [31:0]  rd,                 //  output register (wire!)
    input   [31:0]  rs1,                //  input register 1
    input   [31:0]  rs2,                //  input register 2
    input   [4:0]   fn                  //  5-bit function specifier
);
```

The `fn` immediate "constant" is currently 5 bits, covering encryption,
decryption, and key schedule for both algorithms. Bits `fn[1:0]` specify
the input byte and output rotation while `fn[4:2]` specify the operation.
Appropriate pseudo instruction names for the code points can be proposed;
current identifiers defined in [enc1s.h](enc1s.h) are:

| **Identifier** | **fn[4:2]** | **Description or Use**             |
|----------------|:-----------:|------------------------------------|
| `AES_FN_ENC`   | 0    | AES Encrypt main body with *MixColumns*.  |
| `AES_FN_FWD`   | 1    | AES Encrypt final round / Key Schedule.   |
| `AES_FN_DEC`   | 2    | AES Decrypt main body with *MixColumns*.  |
| `AES_FN_REV`   | 3    | AES Decrypt final round.                  |
| `SM4_FN_ENC`   | 4    | SM4 Encrypt and Decrypt.                  |
| `SM4_FN_KEY`   | 5    | SM4 Key Schedule.                         |
|                | 6-7  | *Unused. 4x6=24 points currently used.*   |


For AES the instruction selects a byte from `rs2`, performs a single S-box
lookup (*SubBytes* or its inverse), evaluates a part of the MDS matrix
(*MixColumns*), rotates the result by a multiple of 8 bits (*ShiftRows*),
and exclusive-ors the result with `rs1` (*AddRoundKey*). Despite its complex
description, it can be seen that hardware implementation of the instructions
is quite compact and the overall software implementation is fast.

For SM4 the instruction has exactly the same data path with byte selection,
S-Box lookup, but with different linear operations, depending on whether
encryption/decryption or key scheduling is being performed.

There is also a secondary primitive `ENC4S`, which may be implemented
as pseudo-instruction. It can be expressed as:
```C

uint32_t enc4s(uint32_t rs1, uint32_t rs2, int fn)
{
    rs1 = enc1s(rs1, rs2, fn);
    rs1 = enc1s(rs1, rs2, fn | 1);
    rs1 = enc1s(rs1, rs2, fn | 2);
    rs1 = enc1s(rs1, rs2, fn | 3);

    return rs1;
}
```

Note that `ENC4S` does **not** to speed up AES encryption and decryption
over `ENC1S`, but does speed up SM4 significantly and also helps make AES key
schedule very fast -- perhaps even faster than fetching the subkeys from
memory. Since four S-Boxes are required for `ENC4S` in a 1-cycle
implementation, implementors may consider their priorities regarding these
two ciphers when deciding if and how to implement `ENC4S`. Some may also
want to drop AES inverse, as decryption in many modes does not actually
require it. The selector input `fn[1:0]` is of course zero in for `ENC4S` --
six code points are required in total and only two for a fast (but large)
implementation of SM4, if `ENC4S` is implemented as a real instruction.
Current assembler code only uses `ENC1S`.


##  Galois/Counter Mode (GCM): AES-GCM with Bitmanip

The Galois/Counter Mode (GCM) specified in
[NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) is a prominent
Authenticated Encryption with Associated Data (AEAD) mechanism. It is
the only cipher mode mandated as "MUST" for all
[TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) implementations.

Here I'll briefly discuss implementation aspects
of AES-GCM using the [bitmanip](https://github.com/riscv/riscv-bitmanip)
(B) extension. Pseudocode for a relevant subset of instructions is contained
in source file [bitmanip.c](bitmanip.c), with prototypes in
[bitmanip.h](bitmanip.h). These are almost directly lifted from the current
draft specification. The instructions relevant to GCM are the Carry-Less
Multiply instructions `CMUL[H][W]` and also the Generalized Reverse `GREV[W]`.
The `[W]` suffix indicates a 64-bit word size variant that is available
only in RV64.

The low-level functions that use these instructions are emulated by
[rv32_ghash.c](rv32_ghash.c) and [rv64_ghash.c](rv64_ghash.c).
I've verified their correctness against full AES-GCM test vectors in the
framework. There may be further room for improvement -- I use such code to
draft the final assembly implementations.

An attempt has been made to pair `CMULH[W]` immediately followed by `CMUL[W]`,
as is done with `MULH`/`MUL`, although there is less of a performance
advantage in this case.


####    Finite Field Arithmetic

While message confidentiality in GCM is provided by a block cipher (AES)
in counter mode (a CTR variant), authentication is based on a GHASH, a
universal hash defined over the binary field GF(2<sup>128</sup>).
Without custom instruction support GCM, just like AES itself, is either
very slow or susceptible to cache timing attacks.

Whether or not authenticating ciphertext or associated data, the main
operation of GCM is the GHASH multiplication between a block of
authentication data and a secret generator "H". The addition in the
field is trivial; just two or four XORs, depending on whether RV32 or RV64
implementation is used.

The finite field is defined to be the ring of binary polynomials modulo
the primitive pentanomial
R(x) = x<sup>128</sup> + x<sup>7</sup> + x<sup>2</sup> + x + 1.
The field encoding is slightly unusual, with the multiplicative identity
(i.e. one -- "1") being encoded as a byte sequence `0x80, 0x00, .., 0x00`.
Converting to little-endian encoding involves inverting bits in each byte;
the `GREV[W]` instruction with constant 7 (pseudo-instruction `rev`)
accomplishes this.

The multiplication itself can be asymptotically sped up with the Karatsuba
method, which works even better in binary fields than it does with integers.
This reduces the number of `CMULW`/`CMULHW` (RV64) pairs from 4 to 3 with
and the number of `CMUL`/`CMULH` (RV32) pairs from 16 to 9, with the
cost of many XORs.


####    Reduction via Shifts or via Multiplication

The second arithmetic step to consider is the polynomial reduction of the
255-bit ring product down to 128 bits (the field) again. The best way of
doing reduction depends on *how fast* the carry-less multiplication
instructions `CMUL[H][W]` are in relation to shifts and XORs.

I'll call these *shift reduction* (based on the low Hamming weight of the
polynomial R) and *multiplication reduction* (which is analogous to
Montgomery and Barrett methods -- albeit simpler because we're working
in characteristic 2.)


####    Estimating the Fastest Method

Examining the multiplication implementations in [rv32_ghash.c](rv32_ghash.c)
and [rv64_ghash.c](rv64_ghash.c) we obtain the following arithmetic counts:

| **Arch** | **Karatsuba**  | **Reduce**    | `GREV` | `XOR` | `S[L/R]L` | `CLMUL` | `CLMULH` |
|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
| RV32B |   no  |   mul |   4   |   36  |   0   |   20  |   20  |
| RV32B |   no  | shift |   4   |   56  |   24  |   16  |   16  |
| RV32B |   yes |   mul |   4   |   52  |   0   |   13  |   13  |
| RV32B |   yes | shift |   4   |   72  |   24  |   9   |   9   |
| RV64B |   no  |   mul |   2   |   10  |   0   |   6   |   6   |
| RV64B |   no  | shift |   2   |   20  |   12  |   4   |   4   |
| RV64B |   yes |   mul |   2   |   14  |   0   |   5   |   5   |
| RV64B |   yes | shift |   2   |   24  |   12  |   3   |   3   |


We can see that the best selection of algorithms depends on the relative
cost of multiplication. Assuming that other instructions have unit cost
and ignoring loops etc, we have:

| **Arch** | **Karatsuba**  | **Reduce**    | **MUL=1** | **MUL=2** | **MUL=3** | **MUL=6** |
|:-----:|:-----:|:-----:|:---------:|:---------:|:---------:|:---------:|
| RV32B |   no  |   mul | **80**    |   120     |   160     | 280       |
| RV32B |   no  | shift |   116     |   148     |   180     | 276       |
| RV32B |   yes |   mul |   82      |   **108** | **134**   | 212       |
| RV32B |   yes | shift |   118     |   136     |   154     | **208**   |
| RV64B |   no  |   mul | **24**    |   **36**  |   48      | 84        |
| RV64B |   no  | shift |   42      |   50      |   58      | 82        |
| RV64B |   yes |   mul |   26      |   **36**  | **46**    | 76        |
| RV64B |   yes | shift |   44      |   50      |   56      | **74**    |

We see that if `CLMUL[H][W]` takes twice the time of XOR and shifts,
or more, then Karatsuba is worthwhile. If these multiplication instructions
are six times slower, or more, then it is worthwhile to convert the reduction multiplications to shifts and XORs.


##  AES Notes

*   AES code density is 16 instructions per round (+ round key fetch), despite
    only requiring a single S-box in hardware. The initial
    [RISC-V Crypto proposal](https://github.com/scarv/riscv-crypto)
    (Section 4.4, "Lightweight AES Acceleration") contains an instruction for
    four parallel S-Box lookups. Without additional helper instructions, this
    will result in a slower round function. Furthermore, the circuit size is
    dominated by the S-Box, so the hardware size of this proposal is lower.
*   In addition to being 500+% faster than plain software implementation
    (depending on table lookup speed), the most important feature of this
    implementation is that it is constant time and resistant to
    [Cache-timing attacks on AES](http://cr.yp.to/antiforgery/cachetiming-20050414.pdf).
    Constant-time implementations of AES are possible in pure software but
    are exceedingly slow.
*   The instructions also support the key schedule; it is possible to compute
    the round keys "on the fly" without committing them to RAM. This may be
    helpful in some types of security applications.
*   Many applications do not actually require the AES inverse function;
    even full TLS implementations may be implemented without it since
    the AES-GCM mode is based on CTR; essentially a stream cipher.
*   Mathematically the AES computation is organized as in the well-known
    "T-Tables" technique, which is more than 20 years old in the context of
    AES. If there are patents for this specific way of organizing the
    computation, they are likely to have expired.
    Other approaches have been considered
    [in the literature](https://iacr.org/archive/ches2006/22/22.pdf).
*   In hardware implementation the AES S-Box and its inverse share much of
    their circuitry. For an example of gate-optimized logic for this purpose,
    see e.g. [Boyar and Peralta](https://eprint.iacr.org/2011/332.pdf).
    We've expanded this to SM4, as can be seen in reference combinatorial
    logic in [hdl/sboxes.v](hdl/sboxes.v).
*   SM4 S-Box is mathematically very close to AES S-Box, as both are based
    on finite field inversion in GF(256). This property also makes the inverse
    S-Box required by AES self-similar to forward S-Box. Even though different
    polynomial bases are used by AES and SM4, finite fields are affine
    equivalent, so much of the circuitry of the three is shared.
    SM4 does not need an inverse S-Box for decryption.


### Testing

Only a C compiler is required to test; RISC-V instruction counts can be
seen from the source code. A [Makefile](Makefile) is provided and the file
[test_main.c](test-main.c) contains a minimal unit test with some standard
test vectors.

```console
$ make
gcc  -c aes_enc.c -o aes_enc.o
gcc  -c sm4_encdec.c -o sm4_encdec.o
gcc  -c aes_dec.c -o aes_dec.o
gcc  -c enc1s.c -o enc1s.o
gcc  -c test_main.c -o test_main.o
gcc  -o xtest aes_enc.o sm4_encdec.o aes_dec.o enc1s.o test_main.o
$ ./xtest
[PASS] AES-128 Enc 69C4E0D86A7B0430D8CDB78070B4C55A
[PASS] AES-128 Dec 00112233445566778899AABBCCDDEEFF
[PASS] AES-192 Enc DDA97CA4864CDFE06EAF70A0EC0D7191
[PASS] AES-192 Dec 00112233445566778899AABBCCDDEEFF
[PASS] AES-256 Enc 8EA2B7CA516745BFEAFC49904B496089
[PASS] AES-256 Dec 00112233445566778899AABBCCDDEEFF
[PASS] AES-128 Enc 3AD77BB40D7A3660A89ECAF32466EF97
[PASS] AES-128 Dec 6BC1BEE22E409F96E93D7E117393172A
[PASS] AES-192 Enc 974104846D0AD3AD7734ECB3ECEE4EEF
[PASS] AES-192 Dec AE2D8A571E03AC9C9EB76FAC45AF8E51
[PASS] AES-256 Enc B6ED21B99CA6F4F9F153E7B1BEAFED1D
[PASS] AES-256 Dec 30C81C46A35CE411E5FBC1191A0A52EF
[PASS] SM4 Encrypt 681EDF34D206965E86B3E94F536E4246
[PASS] SM4 Decrypt 0123456789ABCDEFFEDCBA9876543210
[PASS] SM4 Encrypt F766678F13F01ADEAC1B3EA955ADB594
[PASS] SM4 Decrypt 000102030405060708090A0B0C0D0E0F
[PASS] SM4 Encrypt 865DE90D6B6E99273E2D44859D9C16DF
[PASS] SM4 Decrypt D294D879A1F02C7C5906D6C2D0C54D9F
[PASS] SM4 Encrypt 94CFE3F59E8507FEC41DBE738CCD53E1
[PASS] SM4 Decrypt A27EE076E48E6F389710EC7B5E8A3BE5
< .. GCM tests here .. >
[PASS] all tests passed.
$
```

**Disclaimer and Status**

*   [PQShield](https://pqshield.com) offers no warranty or specific claims of
    standards compliance nor does not endorse this proposal above other
    proposals. PQShield may or may not implement AES and SM4 according to this
    proposal in the future.
*   Despite being proposed in a personal capacity, this proposal
    constitutes a "contribution" as defined in Section 1.4 of the
    RISC-V foundation membership agreement.

Cheers,
- markku

