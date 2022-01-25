CC = gcc
LDFLAGS = -ldl

OBJ := environ heavensgate io loadedso main mmap signal perm

OBJDIR32 = build32
OBJ32 := $(addprefix $(OBJDIR32)/, $(addsuffix .o,$(OBJ))) build32/ctx_32to64.o

OBJDIR64 = build64
OBJ64 := $(addprefix $(OBJDIR64)/, $(addsuffix .o,$(OBJ)))

DEPS := inc/environ.h inc/heavensgate.h inc/io.h inc/loadedso.h inc/mmap.h inc/signal.h inc/perm.h inc/util.h

all: evader32 evader64

evader32: $(OBJ32)
	$(CC) -fPIE -m32 -static $(LDLAGS) $(OBJ32) -o $(OBJDIR32)/$@

evader64: $(OBJ64)
	$(CC) -fPIE -m64 $(LDLAGS) $(OBJ64) -o $(OBJDIR64)/$@

$(OBJDIR32)/ctx_32to64.o: 
	$(CC) -fPIE -m32 -static -c src/ctx_32to64.s -o $@

$(OBJDIR32)/%.o: src/%.c $(DEPS)
	$(CC) -fPIE -m32 -static -c $< -o $@ 

$(OBJDIR64)/%.o: src/%.c $(DEPS)
	$(CC) -fPIE -m64 -c $< -o $@ 

.DEFAULT_GOAL := all

.PHONY: all clean

clean:
	rm -rf build32/*
	rm -rf build64/*