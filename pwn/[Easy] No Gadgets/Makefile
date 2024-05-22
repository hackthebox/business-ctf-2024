default: release

release:
	mkdir -p pwn_no_gadgets
	cp -r challenge pwn_no_gadgets/
	cp htb/vuln.c pwn_no_gadgets/no_gadgets.c
	cp Dockerfile pwn_no_gadgets/
	cp build-docker.sh pwn_no_gadgets/

	echo "HTB{f4k3_fLaG_f0r_t3sTiNg}" > pwn_no_gadgets/challenge/flag.txt

	zip -9 -r pwn_no_gadgets.zip pwn_no_gadgets/
	rm -rf pwn_no_gadgets

	rm -f release/*
	mv pwn_no_gadgets.zip release/

.PHONY: default release