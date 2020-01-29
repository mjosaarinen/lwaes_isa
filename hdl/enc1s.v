//  aes_enc.v
//  2020-01-01  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  The proposed ENC1S lightweight instruction for AES, AES^-1, and SM4 (RV32).


//  Multiply by 0x02 in AES's GF(256) - LFSR style

module aes_xtime( output [7:0] out, input [7:0] in );
    assign  out = { in[6:0], 1'b0 } ^ ( in[7] ? 8'h1B : 8'h00 );
endmodule

//  aes encrypt

module aes_8to32( output [31:0] out, input [7:0] in, input f );

    wire [7:0] x;
    wire [7:0] x2;

    aes_sbox  sbox  ( x,  in );
    aes_xtime lfsr1 ( x2, x  );

    //  NOP / MixColumns MDS Matrix

    assign out = f ? { 24'b0, x } : { x ^ x2, x, x, x2 } ;

endmodule

//  aes decrypt

module aesi_8to32( output [31:0] out, input [7:0] in, input f );

    wire [7:0] x;
    wire [7:0] x2;
    wire [7:0] x4;
    wire [7:0] x8;

    aesi_sbox  sbox  ( x,  in );
    aes_xtime  lfsr1 ( x2, x  );
    aes_xtime  lfsr2 ( x4, x2 );
    aes_xtime  lfsr3 ( x8, x4 );

    //  NOP / Inverse MixColumns MDS Matrix

    assign out = f ? { 24'b0, x } :
        { x ^ x2 ^ x8, x ^ x4 ^ x8, x ^ x8, x2 ^ x4 ^ x8 };

endmodule

//  sm4 encrypt / decrypt

module sm4_8to32( output [31:0] out, input [7:0] in, input f );

    wire [7:0] x;

    sm4_sbox  sbox  ( x,  in );

    //  Either L' or L linear layers (for keying and encrypt / decrypt)
    //  ( this looks slightly odd due to the little-endian byte order )
    assign out = f ? { x[2:0], 5'b0, x[0], 2'b0 ,x[7:3], 1'b0, x[7:1], x } :
        { x[5:0], x, x[7:6], x[7:2], x[1:0] ^ x[7:6], x[7:2] ^ x[5:0], x[1:0] };

endmodule

//  ENC1S instruction

module enc1s(
    output  [31:0]  rs,                 //  output register (wire!)
    input   [31:0]  rs1,                //  input register 1
    input   [31:0]  rs2,                //  input register 2
    input   [4:0]   fn                  //  5-bit function specifier
);

    //  select input byte from rs1 according to fn[1:0]

    wire [7:0] x =  fn[1:0] == 2'b00 ?  rs1[ 7: 0] :
                    fn[1:0] == 2'b01 ?  rs1[15: 8] :
                    fn[1:0] == 2'b10 ?  rs1[23:16] :
                                        rs1[31:24];

    //  expand to 32 bits

    wire [31:0] aes_32;
    wire [31:0] aesi_32;
    wire [31:0] sm4_32;

    aes_8to32   aes     ( aes_32,  x, fn[2] );
    aesi_8to32  aesi    ( aesi_32, x, fn[2] );
    sm4_8to32   sm4     ( sm4_32,  x, fn[2] );

    wire [31:0] y = fn[4:3] == 2'b00 ?  aes_32 :
                    fn[4:3] == 2'b01 ?  aesi_32 :
                    fn[4:3] == 2'b10 ?  sm4_32 : 32'hDEADBABE;

    //  rotate output

    wire [31:0] z = fn[1:0] == 2'b00 ?  y :
                    fn[1:0] == 2'b01 ?  { y[23: 0], y[31:24] } :
                    fn[1:0] == 2'b10 ?  { y[15: 0], y[31:16] } :
                                        { y[ 7: 0], y[31: 8] };

    //  XOR the result with rs2

    assign  rs = z ^ rs2;

endmodule

