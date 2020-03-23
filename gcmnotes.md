The Galois/Counter Mode (GCM) specified in 
[NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) is a prominent
Authenticated Encryption with Associated Data (AEAD) mode. While message
confidentility in GCM is provided by the counter mode, authentication is
based on a GHASH, a universal hash defined over the binary field GF(2^128).

The finite field is defined by the primitive pentanomial
r(x) = x^128 + x^7 + x^2 + x + 1. The field element encoding is slightly
unusual, with the multiplicative identity (usually denoted "1") being
encoded as as byte sequece 0x80, 0x00, .., 0x00. Converting to little-endian
encoding involves inverting bits in each byte; GREV[W] instruction with
constant 7 ("rev") accomplishes this.

The multiplication itself can be sped up with the Karatsuba method,
which applies even more easily binary fields as it done to integers.
This reduces the number of CMULW/CMULHW pairs from 4 to 3 with the
cost of four XORs.

The best way of doing reduction depends on how fast the carry-less
multiplication instructions CMUL[H][W] are in relation to shifts and XORs.


