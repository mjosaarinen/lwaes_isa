# Assembler AES / SM4 using SAES32

2020-02-16  Markku-Juhani O. Saarinen <mjos@pqshield.com>

Assembler implementations of the AES and SM4 block ciphers using the
SAES32 instructions -- has the same prototypes  and features as the
C-language APIs (see parent), so the same unit tests work too.

The functions assume word-aligned input. Typically such low-level "ECB" 
primitives do not work directly on plaintext or ciphertext but are
wrapped in some function that implement an encryption mode such as
CTR, CCM, SIV, or GCM and operate on buffers provided by the wrapper.

This is definitely not the prettiest way of using (custom-0) SAES32
instructions; hacky macros in [saes32_c0.h](saes32_c0.h) are used for
encoding. Requires the C preprocessor, was tested with RISC-V GCC 9.2.0.

Cheers,
- markku

