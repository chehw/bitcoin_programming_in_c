TARGET = tx_parser

CC = gcc
LINKER = gcc -o

#~ CFLAGS = 
CFLAGS = -g -Wall
LIBS = -ldb

SRC_DIR=.
OBJ_DIR=obj


SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

all: do_init $(TARGET)
	echo "objects:" $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(LINKER) $@ $(OBJECTS) $(CFLAGS) $(LIBS)

$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
.PHONY: clean do_init

clean:
	rm -f $(TARGET) $(OBJ_DIR)/*.o

do_init:
	mkdir -p $(OBJ_DIR)
	
