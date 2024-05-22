.PHONY := clean

satellite: binary/main.c library.so
	gcc binary/main.c -lc -L. -l:./library.so -o satellite

library.so: library/library.c library/backdoor.c library/injected.enc
	gcc -fPIC -shared -o library.so library/backdoor.c library/library.c -s

# Copy out .text/.rodata and encrypt the binary
library/injected.enc: library/injected generate.py
	python3 generate.py library/injected library/injected.enc

# Create freestanding binary code to inject
# Optimise a bit to make it small, while disabling optimisations that prevent _start being the first function
library/injected: library/injected.c
	gcc -o library/injected library/injected.c \
		-O1 -fno-inline-functions-called-once -fno-unit-at-a-time \
		-ffreestanding -nostdlib -fno-stack-protector -nostartfiles

clean:
	rm -f satellite library.so library/injected library/injected.enc

# during the war both sides hacked each others communicatioins and satellites
# we need to extract a backdoor to gain control of the satellite
# the password is a admin control pasword
# add satellite ascii art, soil and air quality sensors etc