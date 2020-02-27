#!/usr/bin/env python3

#	yoparse.py
#	2020-02-27	Markku-Juhani O. Saarinen <mjos@pqshield.com>

#	parse the synthesis output

import sys
import time

circ = {}

# parse input files

for fn in sys.argv[1:]:

	print(f"=== summary from {fn}")

	with open(fn, 'r') as f:
		lns = f.readlines()

	li = 0
	targ = ""
	ge = 0.0
	ent = 0
	dep = 0

	for lin in lns:

		li = li + 1
		lv = lin.split();
		ll = len(lv)

		if ll == 3 and lv[0] == "===":
			targ = lv[1]
			ge = 0.0
			ent = 0.0

		if ll == 5 and lv[3] == "transistors:":
			ent = int(lv[4])

		if ll == 6 and lv[1] == "topological":
			tmp = lv[5][8:]
			dep = int(tmp[:2])

		if ll == 2 and lv[0] == "$_AOI3_":
			ge = ge + float(lv[1]) * 1.5

		if ll == 2 and lv[0] == "$_AOI4_":
			ge = ge + float(lv[1]) * 2.0

		if ll == 2 and lv[0] == "$_DFF_P_":
			ge = ge + float(lv[1]) * 4.0

		if ll == 2 and lv[0] == "$_MUX_":
			ge = ge + float(lv[1]) * 3.0

		if ll == 2 and lv[0] == "$_NAND_":
			ge = ge + float(lv[1]) * 1.0

		if ll == 2 and lv[0] == "$_NMUX_":
			ge = ge + float(lv[1]) * 2.5

		if ll == 2 and lv[0] == "$_NOR_":
			ge = ge + float(lv[1]) * 1.0

		if ll == 2 and lv[0] == "$_NOT_":
			ge = ge + float(lv[1]) * 1.0

		if ll == 2 and lv[0] == "$_OAI3_":
			ge = ge + float(lv[1]) * 1.5

		if ll == 2 and lv[0] == "$_OAI4_":
			ge = ge + float(lv[1]) * 2.5

		if ll == 2 and lv[0] == "$_XNOR_":
			ge = ge + float(lv[1]) * 3.0

		if ll == 2 and lv[0] == "$_XOR_":
			ge = ge + float(lv[1]) * 3.0

		if targ != "":
			circ[targ] = ( ge, ent, dep )

for x in circ:

	print(f"{x}: ge={circ[x][0]} tr={circ[x][1]} dep={circ[x][2]}")

