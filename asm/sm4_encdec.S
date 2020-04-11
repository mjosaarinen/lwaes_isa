//	sm4_encdec.S
//	2020-02-16	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	AES Encryption and Key Schedule using "lwaes" instructions.

//	macro definitions for the custom instruction
#include	"enc1s_c0.h"

		.option nopic
		.text
		.align	2


//	Encrypt or decrypt a block, depending on round key ordering.
//		void sm4_encdec(uint8_t out[16], const uint8_t in[16],
//						 const uint32_t rk[SM4_RK_WORDS])
//		where:	a0 = out, a1 = in, a2 = rk

		.globl	sm4_encdec
		.type	sm4_encdec,		 @function

sm4_encdec:
		lw		t0,		0(a1)
		lw		t1,		4(a1)
		lw		t2,		8(a1)
		lw		t3,		12(a1)

		addi	a3,		a2,		128

.loop:
		xor		t4,		t2,		t3

		lw		a1,		0(a2)
		xor		a1,		a1,		t1
		xor		a1,		a1,		t4

		enc1s	T0, T0, A1, SM4_FN_ENC | 0
		enc1s	T0, T0, A1, SM4_FN_ENC | 1
		enc1s	T0, T0, A1, SM4_FN_ENC | 2
		enc1s	T0, T0, A1, SM4_FN_ENC | 3

		lw		a1,		4(a2)
		xor		a1,		a1,		t0
		xor		a1,		a1,		t4

		enc1s	T1, T1, A1, SM4_FN_ENC | 0
		enc1s	T1, T1, A1, SM4_FN_ENC | 1
		enc1s	T1, T1, A1, SM4_FN_ENC | 2
		enc1s	T1, T1, A1, SM4_FN_ENC | 3

		xor		t4,		t0,		t1

		lw		a1,		8(a2)
		xor		a1,		a1,		t3
		xor		a1,		a1,		t4

		enc1s	T2, T2, A1, SM4_FN_ENC | 0
		enc1s	T2, T2, A1, SM4_FN_ENC | 1
		enc1s	T2, T2, A1, SM4_FN_ENC | 2
		enc1s	T2, T2, A1, SM4_FN_ENC | 3

		lw		a1,		12(a2)
		xor		a1,		a1,		t2
		xor		a1,		a1,		t4

		enc1s	T3, T3, A1, SM4_FN_ENC | 0
		enc1s	T3, T3, A1, SM4_FN_ENC | 1
		enc1s	T3, T3, A1, SM4_FN_ENC | 2
		enc1s	T3, T3, A1, SM4_FN_ENC | 3

		addi	a2,		a2,		16
		bne		a3,		a2,		.loop

		sw		t3,		0(a0)
		sw		t2,		4(a0)
		sw		t1,		8(a0)
		sw		t0,		12(a0)

		jr		ra
		.size	sm4_encdec,		 .-sm4_encdec
		.align	2


//	Set key for encryption.
//		void sm4_enc_key(uint32_t rk[32], const uint8_t key[16])
//		where:	a0 = rk, a1 = key

		.globl	sm4_enc_key
		.type	sm4_enc_key,	 @function
sm4_enc_key:
		lw		t0,		0(a1)
		lw		t1,		4(a1)
		lw		t2,		8(a1)
		lw		t3,		12(a1)

		addi	a2,		a0,		128

		//	"fk" constant

		li		a1,		0xC6BAB000
		addi	a1,		a1,		0x1A3
		xor		t0,		t0,		a1

		li		a1,		0x5033A800
		addi	a1,		a1,		0x256
		xor		t1,		t1,		a1

		li		a1,		0x97917800
		addi	a1,		a1,		0x567
		xor		t2,		t2,		a1

		li		a1,		0xDC227000
		addi	a1,		a1,		0x0B2
		xor		t3,		t3,		a1

		//	constants for "ck" generation

		li		a3,		0x140E0000
		addi	a3,		a3,		0x600

		li		a4,		0x1C1C1800
		addi	a4,		a4,		0x41C

		li		a5,		0xFEFEF800
		addi	a5,		a5,		0x6FE

		li		a6,		0x01000000
		addi	a6,		a6,		0x100

.ekl:
		xor		t4,		t2,		t3
		xor		a1,		t1,		a3
		xor		a1,		a1,		t4
		xor		a1,		a1,		a6

		add		a3,		a3,		a4
		and		a3,		a3,		a5

		enc1s	T0, T0, A1, SM4_FN_KEY | 0
		enc1s	T0, T0, A1, SM4_FN_KEY | 1
		enc1s	T0, T0, A1, SM4_FN_KEY | 2
		enc1s	T0, T0, A1, SM4_FN_KEY | 3
		sw		t0,		0(a0)

		xor		a1,		a3,		t0
		xor		a1,		a1,		t4
		xor		a1,		a1,		a6

		add		a3,		a3,		a4
		and		a3,		a3,		a5

		enc1s	T1, T1, A1, SM4_FN_KEY | 0
		enc1s	T1, T1, A1, SM4_FN_KEY | 1
		enc1s	T1, T1, A1, SM4_FN_KEY | 2
		enc1s	T1, T1, A1, SM4_FN_KEY | 3
		sw		t1,		4(a0)

		xor		t4,		t0,		t1
		xor		a1,		t3,		a3
		xor		a1,		a1,		t4
		xor		a1,		a1,		a6

		add		a3,		a3,		a4
		and		a3,		a3,		a5

		enc1s	T2, T2, A1, SM4_FN_KEY | 0
		enc1s	T2, T2, A1, SM4_FN_KEY | 1
		enc1s	T2, T2, A1, SM4_FN_KEY | 2
		enc1s	T2, T2, A1, SM4_FN_KEY | 3
		sw		t2,		8(a0)

		xor		a1,		a3,		t2
		xor		a1,		a1,		t4
		xor		a1,		a1,		a6

		add		a3,		a3,		a4
		and		a3,		a3,		a5

		enc1s	T3, T3, A1, SM4_FN_KEY | 0
		enc1s	T3, T3, A1, SM4_FN_KEY | 1
		enc1s	T3, T3, A1, SM4_FN_KEY | 2
		enc1s	T3, T3, A1, SM4_FN_KEY | 3
		sw		t3,		12(a0)

		addi	a0,		a0,		16

		bne		a2,		a0,		.ekl

		jr		ra
		.size	sm4_enc_key,	 .-sm4_enc_key
		.align	2


//	Set key for decryption.
//		void sm4_dec_key(uint32_t rk[32], const uint8_t key[16])
//			Where:	a0 = rk, a1 = key

		.globl	sm4_dec_key
		.type	sm4_dec_key,	 @function

sm4_dec_key:
		addi	sp,		sp,		-8			//	generate a forward key
		sw		s0,		0(sp)
		sw		ra,		4(sp)
		mv		s0,		a0
		call	sm4_enc_key
		mv		a0,		s0
		lw		s0,		0(sp)
		lw		ra,		4(sp)
		addi	sp,		sp,		8

		addi	a5,		a0,		124			//	flip order
		addi	a2,		a0,		64
.dkl:
		lw		a3,		0(a5)
		lw		a4,		0(a0)
		addi	a0,		a0,		4
		addi	a5,		a5,		-4
		sw		a3,		-4(a0)
		sw		a4,		4(a5)
		bne		a0,		a2,		.dkl

		jr		ra
		.size	sm4_dec_key,	 .-sm4_dec_key

