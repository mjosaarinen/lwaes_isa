//	saes32_dec.S
//	2020-02-16	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	AES Decryption and Key Schedule using "lwaes" instructions.

//	macro definitions for the custom instruction
#include	"saes32_c0.h"

		.option nopic
		.text
		.align	2


//	Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
//		void aes_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
//							const uint32_t rk[], int nr)
//		where: a0 = pt, a1 = ct, a2 = rk, a3 = nr

		.globl	aes_dec_rounds
		.type	aes_dec_rounds,	 @function

aes_dec_rounds:

		lw		t4,		0(a1)				//	load ct
		lw		t5,		4(a1)
		lw		t6,		8(a1)
		lw		a7,		12(a1)

		slli	a3,		a3,		4			//	final pointer
		add		a3,		a3,		a2

		lw		t0,		0(a3)				//	load rk
		lw		t1,		4(a3)
		lw		t2,		8(a3)
		lw		t3,		12(a3)

		xor		t0,		t0,		t4			//	ct ^ rk
		xor		t1,		t1,		t5
		xor		t2,		t2,		t6
		xor		t3,		t3,		a7

		j		.ent						//	enter loop in middle

.loop:
		//	even round
		saes32_decs		T0, T0, T4, 0
		saes32_decs		T0, T0, A7, 1
		saes32_decs		T0, T0, T6, 2
		saes32_decs		T0, T0, T5, 3

		saes32_decs		T1, T1, T5, 0
		saes32_decs		T1, T1, T4, 1
		saes32_decs		T1, T1, A7, 2
		saes32_decs		T1, T1, T6, 3

		saes32_decs		T2, T2, T6, 0
		saes32_decs		T2, T2, T5, 1
		saes32_decs		T2, T2, T4, 2
		saes32_decs		T2, T2, A7, 3

		saes32_decs		T3, T3, A7, 0
		saes32_decs		T3, T3, T6, 1
		saes32_decs		T3, T3, T5, 2
		saes32_decs		T3, T3, T4, 3

.ent:
		addi	a3,		a3,		-32
		lw		t4,		16(a3)				//	load round key
		lw		t5,		20(a3)
		lw		t6,		24(a3)
		lw		a7,		28(a3)

		//	odd round
		saes32_decs		T4, T4, T0, 0
		saes32_decs		T4, T4, T3, 1
		saes32_decs		T4, T4, T2, 2
		saes32_decs		T4, T4, T1, 3

		saes32_decs		T5, T5, T1, 0
		saes32_decs		T5, T5, T0, 1
		saes32_decs		T5, T5, T3, 2
		saes32_decs		T5, T5, T2, 3

		saes32_decs		T6, T6, T2, 0
		saes32_decs		T6, T6, T1, 1
		saes32_decs		T6, T6, T0, 2
		saes32_decs		T6, T6, T3, 3

		saes32_decs		A7, A7, T3, 0
		saes32_decs		A7, A7, T2, 1
		saes32_decs		A7, A7, T1, 2
		saes32_decs		A7, A7, T0, 3

		lw		t0,		0(a3)				//	load round key
		lw		t1,		4(a3)
		lw		t2,		8(a3)
		lw		t3,		12(a3)
		bne		a3,		a2,		.loop

		//	final (output) round
		saes32_decsm	T0, T0, T4, 0
		saes32_decsm	T0, T0, A7, 1
		saes32_decsm	T0, T0, T6, 2
		saes32_decsm	T0, T0, T5, 3

		saes32_decsm	T1, T1, T5, 0
		saes32_decsm	T1, T1, T4, 1
		saes32_decsm	T1, T1, A7, 2
		saes32_decsm	T1, T1, T6, 3

		saes32_decsm	T2, T2, T6, 0
		saes32_decsm	T2, T2, T5, 1
		saes32_decsm	T2, T2, T4, 2
		saes32_decsm	T2, T2, A7, 3

		saes32_decsm	T3, T3, A7, 0
		saes32_decsm	T3, T3, T6, 1
		saes32_decsm	T3, T3, T5, 2
		saes32_decsm	T3, T3, T4, 3

		sw		t0,		0(a0)				//	store pt
		sw		t1,		4(a0)
		sw		t2,		8(a0)
		sw		t3,		12(a0)

		jr		ra
		.size	aes_dec_rounds,	 .-aes_dec_rounds

//	Helper: apply inverse mixcolumns to a vector

		.type	.invmc,	 @function

.invmc:
		lw		t0,		0(a0)

		saes32_encsm	T1, 0,	T0, 0
		saes32_encsm	T1, T1, T0, 1
		saes32_encsm	T1, T1, T0, 2
		saes32_encsm	T1, T1, T0, 3

		saes32_decs		T0, 0,	T1, 0
		saes32_decs		T0, T0, T1, 1
		saes32_decs		T0, T0, T1, 2
		saes32_decs		T0, T0, T1, 3

		sw		t0,		0(a0)
		addi	a0,		a0,		4
		bne		a0,		a1,		.invmc
		jr		ra

		.size	.invmc,	 .-.invmc
		.align	2


//	Key schedule for AES-128 decryption.
//		void aes128_dec_key(uint32_t rk[44], const uint8_t key[16]);
//		where:	a0 = rk, a1 = key

		.globl	aes128_dec_key
		.type	aes128_dec_key,	 @function

aes128_dec_key:
		addi	sp,		sp,		-8
		sw		s0,		0(sp)
		sw		ra,		4(sp)
		mv		s0,		a0
		call	aes128_enc_key
		addi	a0,		s0,		16
		lw		s0,		0(sp)
		lw		ra,		4(sp)
		addi	a1,		a0,		4 * 36
		addi	sp,		sp,		8
		tail	.invmc

		.size	aes128_dec_key,	 .-aes128_dec_key
		.align	2


//	Key schedule for AES-192 decryption.
//		void aes192_dec_key(uint32_t rk[52], const uint8_t key[24]);
//		where:	a0 = rk, a1 = key

		.globl	aes192_dec_key
		.type	aes192_dec_key,	 @function

aes192_dec_key:
		addi	sp,		sp,		-8
		sw		s0,		0(sp)
		sw		ra,		4(sp)
		mv		s0,		a0
		call	aes192_enc_key
		addi	a0,		s0,		16
		lw		s0,		0(sp)
		lw		ra,		4(sp)
		addi	a1,		a0,		4 * 44
		addi	sp,		sp,		8
		tail	.invmc

		.size	aes192_dec_key,	 .-aes192_dec_key
		.align	2


//	Key schedule for AES-256 decryption.
//		void aes256_dec_key(uint32_t rk[60], const uint8_t key[32]);
//		where:	a0 = rk, a1 = key

		.globl	aes256_dec_key
		.type	aes256_dec_key,	 @function

aes256_dec_key:
		addi	sp,		sp,		-8
		sw		s0,		0(sp)
		sw		ra,		4(sp)
		mv		s0,		a0
		call	aes256_enc_key
		addi	a0,		s0,		16
		lw		s0,		0(sp)
		lw		ra,		4(sp)
		addi	a1,		a0,		4 * 52
		addi	sp,		sp,		8
		tail	.invmc

		.size	aes256_dec_key,	 .-aes256_dec_key

