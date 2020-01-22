# lwaes_isa

January 22, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

A lightweight ISA extension proposal for AES (Advanced Encryption Standard)
encryption and decyption with 128/192/256 - bit secret key, as defined in
the [FIPS 197](https://doi.org/10.6028/NIST.FIPS.197) standard.

This package contains a mock implementation of the two instructions together
with full encryption, decryption, and key schedule algorithms for evaluation.

The two instructions are encapsulated in two these two functions 
(located in `aes_enc1s.c` and `aes_dec1s.c`, respecitvely):
```C
uint32_t aes_enc1s(uint32_t rs1, uint32_t rs2, int fn);
uint32_t aes_dec1s(uint32_t rs1, uint32_t rs2, int fn);
```

The instructions select a byte from `rs1`, perform a single S-box
lookup (*SubBytes* or its inverse), compute MDS matrix expansion
(*MixColumns*), rotate the result by a multiple of 8 bits (*ShiftRows*), 
and exclusive-or the result with `rs2` (*AddRoundKey*). Despite complex 
description, it can be seen that hardware implementation of the instructions 
is quite compact and the overall software implementation is compact.

The `fn` immediate "constant" is currently 7 bits, of which 5 are actually
used. The same information can be encoded into 3 bits without affecting
encryption and decryption speeds (key schedule becomes slightly slower).

**Discussion**:
*   Code density is 16 instructions per round (+ round key fetch), despite
    only requiring a single S-box in hardware. The current
    [RISC-V Crypto proposal](https://github.com/scarv/riscv-crypto)
    (Section 4.4, "Lightweight AES Acceleration") contains an instruction for
    4 parallel S-Box lookups. Without additional helper instructions this
    will lead to a slower round function. Furthermore, the circuit size is
    dominated by the S-Box, so hardware size of this proposal is lower.
*   In addition to being 500+% faster than plain software implementation
    (depending on table lookup speed), the most important feature of this
    implementation is that it is constant time and resistant to
    [Cache-timing attacks on AES](http://cr.yp.to/antiforgery/cachetiming-20050414.pdf).
    Constant-time implementations of AES are possible in pure software, but
    are exceedingly slow.
*   The instructions also support key schedule; it is possible to compute
    the round keys "on the fly" without committing them to RAM. This may be
    helpful in some types of security applications.
*   Many applications do not actually require the AES inverse function;
    even full TLS implementations may be implemented without it since the
    the AES-GCM mode is based on CTR; essentially a stream cipher.
*   Mathematically the computation is organized as in the well-known 
	"T-Tables" technique, which is more than 20 years old in the context of 
	AES. If there are patents for this specific way of organizing the 
	computation, they are likely to have expired.
    Other approaches have been considered
    [in the literature](https://iacr.org/archive/ches2006/22/22.pdf).
*   In hardware implementation the S-Box and its inverse share much
    of their circuitry. For an example of gate-optimized logic for this
    purpose, see e.g. [Boyar and Peralta](https://eprint.iacr.org/2011/332.pdf)
*	Other national standard ciphers: If there is support for this type of
	lightweight AES implementation, we can expand the specificatio to 
	offer support to other national ciphers via very similar 
	instructions, and with a similar size-speed tradeoff. 
	SM4, Aria, Cammellia can actually share some of the circuit with the AES
	implementation and Kuznyechik also fits in the same mold.
*   This is a *lightweight* proposal for the RV32/RV64 instruction set; a fast
    implementation would have more than a single S-Box lookup. 

**Disclaimer and Status**

*	[PQShield](https://pqshield.com) offers no warranty or specific claims of 
	standards compliance nor does not endorse this proposal above other
	proposals. [PQSoC](https://pqsoc.com) may or may not implement AES 
	according to this proposal in the future (it currently has a different
	type of AES implementation).
*	Despite being proposed in personal capacity, this proposal
	constitutes a "contribution" as defined in Section 1.4 of the 
	RISC-V foundation membership agreement.

## Testing

You need a C compiler. A `Makefile` is provided and the file `main.c`
contains a minimal unit test with standard test vectors.

```console
$ make
gcc  -c aes_enc1s.c -o aes_enc1s.o
gcc  -c main.c -o main.o
gcc  -c aes_dec1s.c -o aes_dec1s.o
gcc  -o xtest aes_enc1s.o main.o aes_dec1s.o
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
[PASS] all tests passed.
$
```

Cheers,
- markku

