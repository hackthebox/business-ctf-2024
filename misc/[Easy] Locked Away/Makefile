default: release

release:
	mkdir -p misc_locked_away
	cp -r challenge/ misc_locked_away/challenge/
	cp Dockerfile misc_locked_away/
	cp build_docker.sh misc_locked_away/

	echo 'HTB{f4k3_fLaG_f0r_t3sTiNg}' > misc_locked_away/challenge/flag.txt
	chmod +x misc_locked_away/build_docker.sh

	zip -9 -r misc_locked_away.zip misc_locked_away/
	rm -rf misc_locked_away

	rm -f release/*
	mv misc_locked_away.zip release/

.PHONY: default release