CC=gcc

CHALLENGE_DIR=challenge
HEADER_TO_INCLUDE_DIR=$(CHALLENGE_DIR)/libecc/include/
SRC_DIR=$(CHALLENGE_DIR)/libecc/src

# gcc flags from libecc repository
CFLAGS=-Wall -Wextra -pedantic -fno-builtin -std=c99 -D_FORTIFY_SOURCE=2 \
	-fno-stack-protector -O2 -DWITH_STDLIB -fPIC \
	-I$(HEADER_TO_INCLUDE_DIR) -I.

SRC_FILES += $(SRC_DIR)/utils/utils.c $(SRC_DIR)/utils/utils_rand.c
SRC_FILES += $(wildcard $(SRC_DIR)/external_deps/*.c)
SRC_FILES += $(wildcard $(SRC_DIR)/utils/*_nn.c)
SRC_FILES += $(wildcard $(SRC_DIR)/utils/*_fp.c)
SRC_FILES += $(wildcard $(SRC_DIR)/utils/*_buf.c)
SRC_FILES += $(wildcard $(SRC_DIR)/utils/*_curves.c)
SRC_FILES += $(wildcard $(SRC_DIR)/nn/n*.c)
SRC_FILES += $(wildcard $(SRC_DIR)/fp/fp*.c)
SRC_FILES += $(wildcard $(SRC_DIR)/curves/*.c)
SRC_FILES += $(SRC_DIR)/hash/sha256.c $(SRC_DIR)/hash/hash_algs.c
SRC_FILES += $(CHALLENGE_DIR)/aes.c

.PHONY: clean build CHECK_OS

configure:
	@configure.bat

CHECK_OS:
ifneq ($(OS), Windows_NT)
	@echo [-] The challenge must be built in Windows
	@exit -1
else
	@echo [+] Current OS: $(OS)
endif


build: CHECK_OS
	@echo [!] Building challenge ...
	@$(CC) $(CFLAGS) \
	$(SRC_FILES) \
	-o $(CHALLENGE_DIR)/bin/curveware \
	$(CHALLENGE_DIR)/curveware.c
	@echo [+] Challenge was built successfully!

clean: CHECK_OS
	@cls
	@del /q /s "$(CHALLENGE_DIR)\bin\*.exe"
	@rmdir /s /q .\release
	@mkdir .\release

dist:
ifndef name
	@echo [-] Please define the challenge name. For example, \"make prepare name=cool_chall_name\"
	exit -1
endif
	
	@.\challenge\bin\curveware.exe
	
	@mkdir .\release\crypto_$(name)\business-ctf-2025-dev
	@xcopy /F /V /S /Y c:\users\r4sti\business-ctf-2025-dev .\release\crypto_$(name)\business-ctf-2025-dev
	@copy /b .\challenge\bin\curveware.exe .\release\crypto_$(name)\curveware
	@copy .\challenge\README .\release\crypto_$(name)\README
	@7z a -mx9 -r .\release\crypto_$(name).zip .\release\crypto_$(name)
prepare: CHECK_OS clean configure build dist