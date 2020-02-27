#	Makefile
#	2020-01-22	Markku-Juhani O. Saarinen <mjos@pqshield.com>
#   Copyright (c) 2020, PQShield Ltd.  All rights reserved.

#	export all variables to sub-makefiles
export				

BIN		= xtest
CSRC	= $(wildcard *.c)
OBJS	= $(CSRC:.c=.o)
CC		= gcc
#CFLAGS	?= -g -Wall -Wshadow -fsanitize=address,undefined -O2
#CFLAGS	= -Wall -march=native -O3
LIBS    =

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS) $(LIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -rf $(OBJS) $(BIN) *~
	cd hdl && $(MAKE) clean

