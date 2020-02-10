# lwaes_isa

January 22, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

**Updated** January 27, 2020 with SM4.

A lightweight ISA extension proposal for AES (Advanced Encryption Standard)
encryption and decryption with 128/192/256 - bit secret key, as defined in
[FIPS 197](ref/NIST.FIPS.197.pdf). Also implements the SM4
Chinese Encryption algorithm from [GM/T 0002-2012](ref/gmt0002-2012sm4.pdf).
SM4 has only one key size, 128 bits.

A single instruction, `ENC1S` is used for encryption, decryption, and key
schedule for both ciphers.
This package contains a mock implementation of the instruction together
with full encryption, decryption, and key schedule algorithms of
AES-128/192/256 and SM4, intended for instruction counts and other evaluation.
The instruction is encapsulated in a single emulator function in
[enc1s.c](enc1s.c):
```C
uint32_t enc1s(uint32_t rs1, uint32_t rs2, int fn);
```
The file [hdl/enc1s.v](hdl/enc1s.v) contains Verilog combinatorial 
logic for the instruction that can be used in a RISC-V core.
The AES and SM4 S-boxes are defined in [hdl/sboxes.v](hdl/sboxes.v).
```verilog
module enc1s(
    output  [31:0]  rs,                 //  output register (wire!)
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


For AES the instruction selects a byte from `rs1`, performs a single S-box
lookup (*SubBytes* or its inverse), evaluates a part of the MDS matrix
(*MixColumns*), rotates the result by a multiple of 8 bits (*ShiftRows*),
and exclusive-ors the result with `rs2` (*AddRoundKey*). Despite its complex
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
    rs2 = enc1s(rs1, rs2, fn);
    rs2 = enc1s(rs1, rs2, fn | 1);
    rs2 = enc1s(rs1, rs2, fn | 2);
    rs2 = enc1s(rs1, rs2, fn | 3);

    return rs2;
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


**Discussion**:
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
*   In hardware implementation the AES S-Box and its inverse share much f their
    circuitry. For an example of gate-optimized logic for this purpose,
    see e.g. [Boyar and Peralta](https://eprint.iacr.org/2011/332.pdf).
*   SM4 S-Box is mathematically very close to AES S-Box, as both are based
    on finite field inversion in GF(256). This property also makes the inverse
    S-Box required by AES self-similar to forward S-Box. Even though different
    polynomial bases are used by AES and SM4, finite fields are affine
    equivalent, so much of the circuitry of the three is shared.
    SM4 does not need an inverse S-Box for decryption.
*   This is a *lightweight* proposal for the RV32/RV64 instruction set; a fast
    implementation would have more than a single S-Box lookup. The main
    concern here is to resist timing attacks with minimal effort, second is
    performance, and third is that SM4 and other national standards can be
    implemented with very similar speed-size tradeoffs.
*   **Question:** Should we also support Russian GOST R 34.12-2015 Kuznyechik?
    It has a different type of S-Box construction, but it is also 8-8 bit
    and the instruction could be quite similar.

## Testing

Only a C compiler is required to test; RISC-V instruction counts can be
seen from the source code. A [Makefile](Makefile) is provided and the file
[main.c](main.c) contains a minimal unit test with standard test vectors.

```console
$ make
gcc  -c aes_enc.c -o aes_enc.o
gcc  -c sm4_encdec.c -o sm4_encdec.o
gcc  -c aes_dec.c -o aes_dec.o
gcc  -c main.c -o main.o
gcc  -c enc1s.c -o enc1s.o
gcc  -o xtest aes_enc.o sm4_encdec.o aes_dec.o main.o enc1s.o
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
*   This distribution is offered under MIT license agreement, so you're free
    to use the pseudocode to build actual cipher implementations (that's
    what it's for).

Cheers,
- markku

