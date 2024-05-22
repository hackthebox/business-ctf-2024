default: release

release:
	mkdir -p misc_hidden_path
	cp -r challenge misc_hidden_path/
	cp Dockerfile misc_hidden_path/
	cp build_docker.sh misc_hidden_path/

	echo "HTB{f4k3_fL4g_f0R_t3sTiNg}" > misc_hidden_path/challenge/flag.txt
	chmod +x misc_hidden_path/build_docker.sh

	zip -9 -r misc_hidden_path.zip misc_hidden_path/
	rm -rf misc_hidden_path

	rm -f release/*
	mv misc_hidden_path.zip release/

.PHONY: default release