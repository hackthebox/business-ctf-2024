default: release

release:
	mkdir -p pwn_pyrrhus
	cp -r challenge pwn_pyrrhus/
	cp Dockerfile pwn_pyrrhus/
	cp build-docker.sh pwn_pyrrhus/

	echo "HTB{f4k3_fLaG_f0r_t3sTiNg}" > pwn_pyrrhus/challenge/flag.txt
	chmod +x pwn_pyrrhus/build-docker.sh

	zip -9 -r pwn_pyrrhus.zip pwn_pyrrhus/
	rm -rf pwn_pyrrhus

	rm -f release/*
	mv pwn_pyrrhus.zip release/

.PHONY: default release