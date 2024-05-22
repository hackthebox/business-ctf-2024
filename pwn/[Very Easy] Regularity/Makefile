default: compile

compile:
	nasm -f elf64 -o src/source.o src/source.asm
	ld -o challenge/regularity -z execstack src/source.o

release:
	mkdir -p pwn_regularity
	cp challenge/regularity pwn_regularity
	echo "HTB{f4k3_fLaG_f0r_t3sTiNg}" > pwn_regularity/flag.txt
	zip -9 -r pwn_regularity.zip pwn_regularity/
	rm -rf pwn_regularity/

	rm -f release.*
	mv pwn_regularity.zip release/

.PHONY: default compile release