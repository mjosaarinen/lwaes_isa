//	saes32_c0.h
//	2020-02-16	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Raw encoding macros for ENC1S as custom-0 -- pretty ugly.

#ifndef _SAES32_C0_H_
#define _SAES32_C0_H_

//	custom-0 r-type instruction encoding macro

.macro cust0r fn3, fn7, rd, rs1, rs2
	.word(0x0B + ((\fn3) << 12) + ((\fn7) << 25) + ((\rd) << 7) + ((\rs1) << 15) + ((\rs2) << 20))
	.endm


//	function codes
#define SAES32_ENCSM_FN		0
#define SAES32_ENCS_FN		1
#define SAES32_DECSM_FN		2
#define SAES32_DECS_FN		3
#define SSM4_ED_FN			4
#define SSM4_KS_FN			5

//	SAES32 as funct3=0 -- with a fn in funct7

	.macro	saes32			rd, rs1, rs2, fn
	cust0r	0, \fn, \rd, \rs1, \rs2
	.endm

//	Pseudo-ops for AES and SM4

	.macro	saes32_encsm	rd, rs1, rs2, bs
	saes32	\rd, \rs1, \rs2, ((SAES32_ENCSM_FN << 2) | (\bs))
	.endm

	.macro	saes32_encs		rd, rs1, rs2, bs
	saes32	\rd, \rs1, \rs2, ((SAES32_ENCS_FN << 2) | (\bs))
	.endm

	.macro	saes32_decsm	rd, rs1, rs2, bs
	saes32	\rd, \rs1, \rs2, ((SAES32_DECSM_FN << 2) | (\bs))
	.endm

	.macro	saes32_decs		rd, rs1, rs2, bs
	saes32	\rd, \rs1, \rs2, ((SAES32_DECS_FN << 2) | (\bs))
	.endm


	.macro	ssm4_ed			rd, rs1, rs2, bs
	saes32	\rd, \rs1, \rs2, ((SSM4_ED_FN << 2) | (\bs))
	.endm

	.macro	ssm4_ks			rd, rs1, rs2, bs
	saes32	\rd, \rs1, \rs2, ((SSM4_KS_FN << 2) | (\bs))
	.endm


//	numbered registers
#define X0	0
#define RA	1
#define SP	2
#define GP	3
#define TP	4
#define T0	5
#define T1	6
#define T2	7
#define S0	8
#define S1	9
#define A0	10
#define A1	11
#define A2	12
#define A3	13
#define A4	14
#define A5	15
#define A6	16
#define A7	17
#define S2	18
#define S3	19
#define S4	20
#define S5	21
#define S6	22
#define S7	23
#define S8	24
#define S9	25
#define S10 26
#define S11 27
#define T3	28
#define T4	29
#define T5	30
#define T6	31

#endif
