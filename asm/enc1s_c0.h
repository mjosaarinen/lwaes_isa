//  enc1s_c0.h
//  2020-02-16  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Raw encoding macros for ENC1S as custom-0 -- pretty ugly.

#ifndef _ENC1S_C0_H_
#define _ENC1S_C0_H_

//  custom-0 r-type instruction encoding macro

.macro  cust0r  fn3, fn7, rd, rs1, rs2
        .word   (0x0B + ((\fn3) << 12) + ((\fn7) << 25) + \
                ((\rd) << 7) + ((\rs1) << 15)  + ((\rs2) << 20))
.endm

//  ENC1S as funct3=0 -- with a fn in funct7

.macro  enc1s   rd, rs1, rs2, fn
        cust0r  0, \fn, \rd, \rs1, \rs2
.endm

//  function codes

#define AES_FN_ENC  (0 << 2)
#define AES_FN_FWD  (1 << 2)
#define AES_FN_DEC  (2 << 2)
#define AES_FN_REV  (3 << 2)
#define SM4_FN_ENC  (4 << 2)
#define SM4_FN_KEY  (5 << 2)

//  numbered registers

#define X0  0
#define RA  1
#define SP  2
#define GP  3
#define TP  4
#define T0  5
#define T1  6
#define T2  7
#define S0  8
#define S1  9
#define A0  10
#define A1  11
#define A2  12
#define A3  13
#define A4  14
#define A5  15
#define A6  16
#define A7  17
#define S2  18
#define S3  19
#define S4  20
#define S5  21
#define S6  22
#define S7  23
#define S8  24
#define S9  25
#define S10 26
#define S11 27
#define T3  28
#define T4  29
#define T5  30
#define T6  31

#endif
