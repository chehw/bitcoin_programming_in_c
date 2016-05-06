TARGET_TEST=test
TARGET_SERVER=server

CC=gcc
LINKER = gcc -o

CFLAGS = -I. -Ibase
CFLAGS += -g -Wall -D_GNU_SOURCE
CFLAGS += -D_DEBUG
CFLAGS += $(shell pkg-config --cflags json-c)

LIBS = -lpthread
LIBS += $(shell pkg-config --libs json-c)

SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = .

BASE_SRC_DIR = base
BASE_OBJ_DIR = obj/base


SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BASE_SOURCES := $(wildcard $(BASE_SRC_DIR)/*.c)
BASE_OBJECTS := $(BASE_SOURCES:$(BASE_SRC_DIR)/%.c=$(BASE_OBJ_DIR)/%.o)

.PHONY: all do_init clean

all: do_init $(BIN_DIR)/$(TARGET_TEST)

$(BIN_DIR)/$(TARGET_TEST): $(OBJECTS) $(BASE_OBJECTS)
	$(LINKER) $@ $(OBJECTS) $(BASE_OBJECTS) $(LIBS)
	
$(OBJECTS): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $< -o $@ $(CFLAGS)
	
$(BASE_OBJECTS): $(BASE_OBJ_DIR)/%.o: $(BASE_SRC_DIR)/%.c
	$(CC) -c $< -o $@ $(CFLAGS)
	
do_init:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(BASE_OBJ_DIR)
	
clean:
	rm -f $(OBJECTS) $(BIN_DIR)/$(TARGET_TEST) $(BASE_OBJECTS)

