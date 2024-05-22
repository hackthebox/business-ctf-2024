all:
	gcc -masm=intel -o challenge/insidious source.c -lseccomp
	x86_64-linux-musl-gcc -masm=intel -fno-pie -no-pie -static -o exploit/test exploit/test.c
	gcc -shared ./exploit/passcode.c -o exploit/passcode.so
clean: 
	rm challenge/insidious exploit/passcode.so exploit/test