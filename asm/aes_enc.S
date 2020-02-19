//  aes_enc.S
//  2020-02-16  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES Encryption and Key Schedule using "lwaes" instructions.

//  macro definitions for the custom instruction
#include    "enc1s_c0.h"

        .option nopic
        .text
        .align  2


//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
//      void aes_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
//                          const uint32_t rk[], int nr)
//      where:  a0 = ct, a1 = pt, a2 = rk, a3 = nr

        .globl  aes_enc_rounds
        .type   aes_enc_rounds,  @function

aes_enc_rounds:

        lw      t4,     0(a1)               //  load pt
        lw      t5,     4(a1)
        lw      t6,     8(a1)
        lw      a7,     12(a1)

        lw      t0,     0(a2)               //  load rk
        lw      t1,     4(a2)
        lw      t2,     8(a2)
        lw      t3,     12(a2)

        xor     t0,     t0,     t4          //  pt ^ rk
        xor     t1,     t1,     t5
        xor     t2,     t2,     t6
        xor     t3,     t3,     a7

        slli    a3,     a3,     4           //  final pointer
        add     a3,     a3,     a2

        j       .ent                        //  enter loop in the middle

.loop:
        //  odd round
        enc1s   T0, T0, T4, AES_FN_ENC | 0
        enc1s   T0, T0, T5, AES_FN_ENC | 1
        enc1s   T0, T0, T6, AES_FN_ENC | 2
        enc1s   T0, T0, A7, AES_FN_ENC | 3

        enc1s   T1, T1, T5, AES_FN_ENC | 0
        enc1s   T1, T1, T6, AES_FN_ENC | 1
        enc1s   T1, T1, A7, AES_FN_ENC | 2
        enc1s   T1, T1, T4, AES_FN_ENC | 3

        enc1s   T2, T2, T6, AES_FN_ENC | 0
        enc1s   T2, T2, A7, AES_FN_ENC | 1
        enc1s   T2, T2, T4, AES_FN_ENC | 2
        enc1s   T2, T2, T5, AES_FN_ENC | 3

        enc1s   T3, T3, A7, AES_FN_ENC | 0
        enc1s   T3, T3, T4, AES_FN_ENC | 1
        enc1s   T3, T3, T5, AES_FN_ENC | 2
        enc1s   T3, T3, T6, AES_FN_ENC | 3

.ent:
        lw      t4,     16(a2)              //  load round key
        lw      t5,     20(a2)
        lw      t6,     24(a2)
        lw      a7,     28(a2)

        //  even round
        enc1s   T4, T4, T0, AES_FN_ENC | 0
        enc1s   T4, T4, T1, AES_FN_ENC | 1
        enc1s   T4, T4, T2, AES_FN_ENC | 2
        enc1s   T4, T4, T3, AES_FN_ENC | 3

        enc1s   T5, T5, T1, AES_FN_ENC | 0
        enc1s   T5, T5, T2, AES_FN_ENC | 1
        enc1s   T5, T5, T3, AES_FN_ENC | 2
        enc1s   T5, T5, T0, AES_FN_ENC | 3

        enc1s   T6, T6, T2, AES_FN_ENC | 0
        enc1s   T6, T6, T3, AES_FN_ENC | 1
        enc1s   T6, T6, T0, AES_FN_ENC | 2
        enc1s   T6, T6, T1, AES_FN_ENC | 3

        enc1s   A7, A7, T3, AES_FN_ENC | 0
        enc1s   A7, A7, T0, AES_FN_ENC | 1
        enc1s   A7, A7, T1, AES_FN_ENC | 2
        enc1s   A7, A7, T2, AES_FN_ENC | 3

        addi    a2,     a2,     32
        lw      t0,     0(a2)               //  load round key
        lw      t1,     4(a2)
        lw      t2,     8(a2)
        lw      t3,     12(a2)
        bne     a3,     a2,     .loop

        //  final (output) round
        enc1s   T0, T0, T4, AES_FN_FWD | 0
        enc1s   T0, T0, T5, AES_FN_FWD | 1
        enc1s   T0, T0, T6, AES_FN_FWD | 2
        enc1s   T0, T0, A7, AES_FN_FWD | 3

        enc1s   T1, T1, T5, AES_FN_FWD | 0
        enc1s   T1, T1, T6, AES_FN_FWD | 1
        enc1s   T1, T1, A7, AES_FN_FWD | 2
        enc1s   T1, T1, T4, AES_FN_FWD | 3

        enc1s   T2, T2, T6, AES_FN_FWD | 0
        enc1s   T2, T2, A7, AES_FN_FWD | 1
        enc1s   T2, T2, T4, AES_FN_FWD | 2
        enc1s   T2, T2, T5, AES_FN_FWD | 3

        enc1s   T3, T3, A7, AES_FN_FWD | 0
        enc1s   T3, T3, T4, AES_FN_FWD | 1
        enc1s   T3, T3, T5, AES_FN_FWD | 2
        enc1s   T3, T3, T6, AES_FN_FWD | 3

        sw      t0,     0(a0)               //  store ct
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        jr      ra
        .size   aes_enc_rounds,  .-aes_enc_rounds


//  Key schedule for AES-128 Encryption.
//      void aes128_enc_key(uint32_t rk[44], const uint8_t key[16])
//      where:  a0 = rk, a1 = key

        .align  2
        .globl  aes128_enc_key
        .type   aes128_enc_key,  @function

aes128_enc_key:

        lui     a2,     %hi(.rcon)          //  rcon pointer
        addi    a2,     a2,     %lo(.rcon)

        addi    a3,     a0,     16 * 10     //  end pointer

        lw      t0,     0(a1)               //  input key
        lw      t1,     4(a1)
        lw      t2,     8(a1)
        lw      t3,     12(a1)

        sw      t0,     0(a0)               //  first round key
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        xori    t0,     t0,     1           //  first round constant
        j       .nl0

.ekl0:
        addi    a2,     a2,     1
        lbu     a1,     0(a2)               //  round constant
        xor     t0,     a1,     t0

.nl0:
        slli    a4,     t3,     24          //  rotate
        srli    a1,     t3,     8
        or      a1,     a1,     a4

        enc1s   T0, T0, A1, AES_FN_FWD | 0
        enc1s   T0, T0, A1, AES_FN_FWD | 1
        enc1s   T0, T0, A1, AES_FN_FWD | 2
        enc1s   T0, T0, A1, AES_FN_FWD | 3

        xor     t1,     t1,     t0
        xor     t2,     t2,     t1
        xor     t3,     t3,     t2

        addi    a0,     a0,     16
        sw      t0,     0(a0)               //  store round key
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        bne     a0,     a3,     .ekl0

        jr      ra
        .size   aes128_enc_key,  .-aes128_enc_key


//  Key schedule for AES-192 Encryption.
//      void aes192_enc_key(uint32_t rk[52], const uint8_t key[16])
//      where:  a0 = rk, a1 = key

        .align  2
        .globl  aes192_enc_key
        .type   aes192_enc_key,  @function

aes192_enc_key:

        lui     a2,     %hi(.rcon)          //  rcon pointer
        addi    a2,     a2,     %lo(.rcon)

        addi    a3,     a0,     16 * 12     //  end pointer

        lw      t0,     0(a1)               //  input key
        lw      t1,     4(a1)
        lw      t2,     8(a1)
        lw      t3,     12(a1)
        lw      t4,     16(a1)
        lw      t5,     20(a1)

        sw      t0,     0(a0)               //  first round key
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        xori    t0,     t0,     1           //  first round constant
        j       .nl1

.ekl1:  addi    a2,     a2,     1
        lbu     a1,     0(a2)               //  round constant
        xor     t0,     a1,     t0

.nl1:   sw      t4,     16(a0)              //  high part of round key
        sw      t5,     20(a0)

        slli    a4,     t5,     24          //  rotate
        srli    a1,     t5,     8
        or      a1,     a1,     a4

        enc1s   T0, T0, A1, AES_FN_FWD | 0
        enc1s   T0, T0, A1, AES_FN_FWD | 1
        enc1s   T0, T0, A1, AES_FN_FWD | 2
        enc1s   T0, T0, A1, AES_FN_FWD | 3

        xor     t1,     t1,     t0
        xor     t2,     t2,     t1
        xor     t3,     t3,     t2
        xor     t4,     t4,     t3
        xor     t5,     t5,     t4

        addi    a0,     a0,     24
        sw      t0,     0(a0)               //  store round key
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        bne     a0,     a3,     .ekl1

        jr      ra
        .size   aes192_enc_key,  .-aes192_enc_key


//  Key schedule for AES-256 Encryption.
//      void aes256_enc_key(uint32_t rk[60], const uint8_t key[16])
//      where:  a0 = rk, a1 = key

        .align  2
        .globl  aes256_enc_key
        .type   aes256_enc_key,  @function

aes256_enc_key:

        lui     a2,     %hi(.rcon)          //  rcon pointer
        addi    a2,     a2,     %lo(.rcon)

        addi    a3,     a0,     16 * 14     //  end pointer

        lw      t0,     0(a1)               //  input key
        lw      t1,     4(a1)
        lw      t2,     8(a1)
        lw      t3,     12(a1)
        lw      t4,     16(a1)
        lw      t5,     20(a1)
        lw      t6,     24(a1)
        lw      a7,     28(a1)

        sw      t0,     0(a0)               //  first round key
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        xori    t0,     t0,     1           //  first round constant
        j       .nl2

.ekl2:  enc1s   T4, T4, T3, AES_FN_FWD | 0  //  no rotate
        enc1s   T4, T4, T3, AES_FN_FWD | 1
        enc1s   T4, T4, T3, AES_FN_FWD | 2
        enc1s   T4, T4, T3, AES_FN_FWD | 3

        xor     t5,     t5,     t4
        xor     t6,     t6,     t5
        xor     a7,     a7,     t6

        addi    a2,     a2,     1
        lbu     a1,     0(a2)               //  round constant
        xor     t0,     a1,     t0

.nl2:   sw      t4,     16(a0)              //  store upper part of rk
        sw      t5,     20(a0)
        sw      t6,     24(a0)
        sw      a7,     28(a0)

        slli    a4,     a7,     24          //  rotate
        srli    a1,     a7,     8
        or      a1,     a1,     a4

        enc1s   T0, T0, A1, AES_FN_FWD | 0
        enc1s   T0, T0, A1, AES_FN_FWD | 1
        enc1s   T0, T0, A1, AES_FN_FWD | 2
        enc1s   T0, T0, A1, AES_FN_FWD | 3

        xor     t1,     t1,     t0
        xor     t2,     t2,     t1
        xor     t3,     t3,     t2

        addi    a0,     a0,     32

        sw      t0,     0(a0)               //  store round key
        sw      t1,     4(a0)
        sw      t2,     8(a0)
        sw      t3,     12(a0)

        bne     a0,     a3,     .ekl2       //  final rk ?

        jr      ra
        .size   aes256_enc_key,  .-aes256_enc_key

//  round constants

        .type   .rcon,  @object
.rcon:
        .byte   0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        .size   .rcon,  10

