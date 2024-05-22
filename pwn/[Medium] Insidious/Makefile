default: release

release:
	mkdir -p pwn_insidious
	cp -r challenge pwn_insidious/
	cp Dockerfile pwn_insidious/
	cp build_docker.sh pwn_insidious/

	echo "HTB{f4k3_fLaG_f0r_t3sTiNg}" > pwn_insidious/challenge/flag.txt
	chmod +x pwn_insidious/build_docker.sh

	zip -9 -r pwn_insidious.zip pwn_insidious/
	rm -rf pwn_insidious

	rm -f release/*
	mv pwn_insidious.zip release/

.PHONY: default release