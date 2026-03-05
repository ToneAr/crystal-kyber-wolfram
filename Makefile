# Makefile -- Build CRYSTAL-Kyber LibraryLink shared library
#
# Compiles the kyber/ref sources three times (K=2,3,4) with unique symbol
# namespaces, then links them with the LibraryLink wrapper into a single .so.
# Shared sources (fips202, randombytes) are compiled only once.

WOLFRAM_DIR ?= $(HOME)/Wolfram/Wolfram/15.0
WOLFRAM_INC  = $(WOLFRAM_DIR)/SystemFiles/IncludeFiles/C
KYBER_REF    = kyber/ref

CC       = gcc
CFLAGS   = -O2 -Wall -Wextra -fPIC -I$(WOLFRAM_INC) -I$(KYBER_REF)
LDFLAGS  = -shared

# Output
BUILD_DIR = LibraryResources/Linux-x86-64
TARGET    = $(BUILD_DIR)/kyber_link.so

# K-dependent sources (symbols are namespaced by KYBER_K)
KYBER_K_SRCS = cbd.c indcpa.c kem.c ntt.c poly.c polyvec.c \
               reduce.c symmetric-shake.c verify.c

# K-independent shared sources (compiled once)
SHARED_SRCS = fips202.c randombytes.c

# Object files per security level (K-dependent only)
OBJ_512  = $(patsubst %.c,build/kyber512/%.o,$(KYBER_K_SRCS))
OBJ_768  = $(patsubst %.c,build/kyber768/%.o,$(KYBER_K_SRCS))
OBJ_1024 = $(patsubst %.c,build/kyber1024/%.o,$(KYBER_K_SRCS))

# Shared objects (compiled once)
OBJ_SHARED = $(patsubst %.c,build/shared/%.o,$(SHARED_SRCS))

# Wrapper
OBJ_LINK = build/kyber_link.o

ALL_OBJS = $(OBJ_SHARED) $(OBJ_512) $(OBJ_768) $(OBJ_1024) $(OBJ_LINK)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(ALL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $^

# Shared sources (K-independent, compiled once)
build/shared/%.o: $(KYBER_REF)/%.c
	@mkdir -p build/shared
	$(CC) $(CFLAGS) -DKYBER_K=3 -c $< -o $@

# Kyber512 (K=2)
build/kyber512/%.o: $(KYBER_REF)/%.c
	@mkdir -p build/kyber512
	$(CC) $(CFLAGS) -DKYBER_K=2 -c $< -o $@

# Kyber768 (K=3)
build/kyber768/%.o: $(KYBER_REF)/%.c
	@mkdir -p build/kyber768
	$(CC) $(CFLAGS) -DKYBER_K=3 -c $< -o $@

# Kyber1024 (K=4)
build/kyber1024/%.o: $(KYBER_REF)/%.c
	@mkdir -p build/kyber1024
	$(CC) $(CFLAGS) -DKYBER_K=4 -c $< -o $@

# LibraryLink wrapper
build/kyber_link.o: src/kyber_link.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build $(BUILD_DIR)/kyber_link.so