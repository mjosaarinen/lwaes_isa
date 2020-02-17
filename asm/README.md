# Assembler AES / SM4 using ENC1S

2020-02-16  Markku-Juhani O. Saarinen <mjos@pqshield.com>

Assembler implementations of the AES and SM4 block ciphers using the
ENC1S instruction -- has the same prototypes  and features as the
C-language APIs (see parent), so the same unit tests work too.

The functions assume word-aligned input. Typically such low-level "ECB" 
primitives do not work directly on plaintext or ciphertext but are
wrapped in some function that implement an encryption mode such as
CTR, CCM, SIV, or GCM and operate on buffers provided by the wrapper.

This is definitely not the prettiest way of using (custom-0) ENC1s
instructions; hacky macros in [enc1s_c0.h](enc1s_c0.h) are used in
encoding. Uses the C preprocessor, and was tested with RISC-V GCC 9.2.0.

Cheers,
- markku

