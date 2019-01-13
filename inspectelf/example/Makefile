# include proj.mk
SRCS=sha.c
PROJ=sha

CFLAGS=-fstack-protector-all -s -O3
CFLAGS+=-I/home/giliy/openssl/include/
WFLAGS=-Wall -Wextra -pedantic -Werror
LFLAGS=-Wl,-z,relro,-z,now
LFLAGS+=-L/home/giliy/openssl
LFLAGS+=-lcrypto
OFLAGS=-pipe

CROSS_COMPILE=aarch64-linux-gnu-

CC=${CROSS_COMPILE}gcc
LD=${CROSS_COMPILE}gcc

OBJS = $(SRCS:%.c=%.o)

all: sha
	@echo "Done"

em: clean
	@make CROSS=emulate

$(PROJ): $(OBJS)
	@echo "Linking: \033[0;32m$@\033[0m"
	@$(LD) $(OBJS) $(LFLAGS) $(OFLAGS) -o $@

%.o: %.c
	@echo "Compiling \033[0;31m$<\033[0m"
	@$(CC) $(CFLAGS) $(DFLAGS) $(WFLAGS) $(OFLAGS) -c $< -o $@

clean: clean_objects
	@rm -f $(PROJ)
	@echo "Clean"

clean_objects:
	@rm -f *.o
	@echo "Cleaning objects..."
