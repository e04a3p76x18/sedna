NAME=sedna
CFLAGS=-g -w -o $(NAME)
GTKFLAGS= -lnfnetlink -lnetfilter_queue -std=c11 `pkg-config --cflags gtk+-3.0` `pkg-config --libs gtk+-3.0`
SRCS=main.c
CC=gcc

# top-level rule to create the program.
all: main

# compiling the source file.
main: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) $(GTKFLAGS)

# cleaning everything that can be automatically recreated with "make".
clean:
	/bin/rm -f $(NAME)
