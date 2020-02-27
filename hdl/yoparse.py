#!/usr/bin/env python3

#	yoparse.py
#	2020-02-27	Markku-Juhani O. Saarinen <mjos@pqshield.com>

#	parse the synthesis output

import sys

# "For evaluation purposes we [use] the following mockup ASIC cell library:"

wt = {}
wt["$_NOT_"]	= 0.5
wt["$_NAND_"]	= 1.0
wt["$_NOR_"]	= 1.0
wt["$_XOR_"]	= 3.0
wt["$_XNOR_"]	= 3.0
wt["$_DFF_P_"]	= 4.0
wt["$_AOI3_"]	= 1.5
wt["$_OAI3_"]	= 1.5
wt["$_AOI4_"]	= 2.0
wt["$_OAI4_"]	= 2.0
wt["$_NMUX_"]	= 2.5
wt["$_MUX_"]	= 3.0

# parse input files

for fn in sys.argv[1:]:

	print(f"=== summary from {fn}")

	with open(fn, 'r') as f:
		lns = f.readlines()

	circ = {}
	li = 0
	targ = ""
	ge = 0.0
	tr = 0
	ltp = 0

	for lin in lns:

		li = li + 1
		lv = lin.split();
		ll = len(lv)

		if ll == 3 and lv[0] == "===":
			targ = lv[1]
			ge = 0.0
			tr = 0
			ltp = 0

		if ll == 5 and lv[3] == "transistors:":
			tr = int(lv[4])

		if ll == 6 and lv[1] == "topological":
			tmp = lv[5][8:]
			ltp = int(tmp[:-2])

		if ll == 2 and lv[0][:2] == "$_":
			if lv[0] in wt:
				ge = ge + float(lv[1]) * wt[lv[0]]
			else:
				print(f"{fn}:{li} unknown gate {lv[0]}")

		# update it
		if targ != "":
			circ[targ] = ( ge, tr, ltp )

	# print the counts

	for x in circ:
		print(f"{x:20}  ge={circ[x][0]:7}  tr={circ[x][1]:5}  ltp={circ[x][2]:3}")

