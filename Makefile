# FxCrypt Makefile
INCLUDES=-I include -I lib
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

OBJS = \
	bin/startup.o \
	bin/fxcrypt.o

all: host

internal: prepare
	@echo "  CC    src/startup.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/startup.c -o bin/startup.o
	@echo "  CC    lib/fxcrypt.c"
	@$(CC) $(CFLAGS) $(INCLUDES) lib/fxcrypt.c -o bin/fxcrypt.o
	@echo "  LD    bin/fxcrypt"
	@$(LD) -o bin/fxcrypt $(OBJS) $(LDFLAGS)

prepare:
	@mkdir -p bin

host:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -O2 -ffunction-sections -fdata-sections -Wstrict-prototypes' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax -lmbedcrypto'

install:
	@cp -v bin/fxcrypt /usr/bin/fxcrypt

uninstall:
	@rm -fv /usr/bin/fxcrypt

indent:
	@indent $(INDENT_FLAGS) ./*/*.h
	@indent $(INDENT_FLAGS) ./*/*.c
	@rm -rf ./*/*~

clean:
	@echo "  CLEAN ."
	@rm -rf bin

analysis:
	@scan-build make
	@cppcheck --force */*.h
	@cppcheck --force */*.c
