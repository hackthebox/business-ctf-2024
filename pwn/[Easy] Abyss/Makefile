default: release

release:
	mkdir -p pwn_abyss
	cp -r challenge pwn_abyss/
	cp Dockerfile pwn_abyss/
	cp build-docker.sh pwn_abyss/

	echo "HTB{f4k3_fLaG_f0r_t3sTiNg}" > pwn_abyss/challenge/flag.txt
	chmod +x pwn_abyss/build-docker.sh

	zip -9 -r pwn_abyss.zip pwn_abyss/
	rm -rf pwn_abyss

	rm -f release/*
	mv pwn_abyss.zip release/

.PHONY: default release