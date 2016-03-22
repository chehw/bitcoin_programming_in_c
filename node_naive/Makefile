TARGET=node_naive

CC=gcc -Wall -std=c99 -D_GNU_SOURCE
LINKER=gcc -std=c99 -D_GNU_SOURCE -O6 -o

CFLAGS=-I.

LIBS=-lpthread -lm

INCLUDE_FILE=init.impl.h

SRC_DIR=.
OBJ_DIR=obj

SOURCES = main.c sig_handler.c sha256.c ripemd160.c chutil.c base58.c
SOURCES += merkle_tree.c
SOURCES += node.c
SOURCES += satoshi_protocol.c

OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)

all: do_init $(TARGET) Makefile

$(TARGET): $(OBJECTS) $(INCLUDE_FILE)
	$(LINKER) $@ $(OBJECTS) $(CFLAGS) $(LIBS)
	
$(OBJECTS): $(OBJ_DIR)/%.o : %.c $(INCLUDE_FILE)
	$(CC) -c $< -o $@ $(CFLAGS)



.PHONY: clean do_init
clean:
	rm -f $(TARGET) $(OBJECTS)
	rmdir $(OBJ_DIR)

do_init:
	mkdir -p $(OBJ_DIR)
