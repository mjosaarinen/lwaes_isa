#	Makefile
#	2020-01-29  Markku-Juhani O. Saarinen <mjos@pqshield.com>
#	Copyright (c) 2020, PQShield Ltd.  All rights reserved.

#	Minimal makefile for Icarus verilog

HDL		= 	$(wildcard *.v)
SIM		=	sim.vvp

#	simulate

sim:	$(SIM)
	vvp -N $(SIM)

$(SIM):	$(HDL)
	iverilog -o sim.vvp $(HDL)

#	synthesis and reporting

synth.tmp:	$(HDL) synth.ys
	rm -f synth.tmp
	yosys -v1 synth.ys

rep:	synth.tmp
	./yoparse.py synth.tmp

#	prints differing lines

test:	$(SIM)
	vvp -n $(SIM) | grep "[TB]" | diff - tbref.txt

clean:
	rm -f	$(SIM) synth.tmp

