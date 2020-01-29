//  enc1s_tb.v
//  2020-01-29  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  test bench for the AES / SM4 instruction

`timescale  1 ns / 1 ps

module enc1s_tb;

    //  clock generator
    reg clk = 1;
    always #5 clk = ~clk;

    reg [31:0] cnt = 0;

    reg [31:0]  rs1 = 32'h00000000;
    reg [31:0]  rs2 = 32'h00000000;
    reg [4:0]   fn  = 0;
    wire [31:0] rd;

    wire [7:0] box;

    //  test instance
    enc1s tb0 ( rd, rs1, rs2, fn );

    always @(posedge clk) begin

    $display("[TB] rd=%h rs1=%h rs2=%h fn=%h", rd, rs1, rs2, fn );

        fn  <= fn  + 1;
        rs1 <= rs1 + 32'h01234567;

        if (cnt == 23) begin
            $finish;
        end
        cnt <= cnt + 1;
    end


endmodule

