TARGET=server-debug

CC=gcc
CFLAGS=-Wall -I. -g
LIBS=-lcrypto -lssl

LINKER=gcc -o

SRCDIR=.
INCDIR=.
OBJDIR=.
BINDIR=.

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)


$(BINDIR)/$(TARGET): $(OBJECTS) 
	$(LINKER) $@ $(OBJECTS) $(LIBS)

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c 
	$(CC) -c $< -o $@ $(CFLAGS)
	
.PHONY: clean
clean:
	@rm -f $(OBJECTS) $(BINDIR)/$(TARGET)
