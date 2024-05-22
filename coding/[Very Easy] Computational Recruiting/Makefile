default: release

release:
	mkdir -p coding_computational_recruiting
	cp challenge/data.txt coding_computational_recruiting
	zip -9 -r coding_computational_recruiting.zip coding_computational_recruiting/
	rm -rf coding_computational_recruiting/

	rm -f release/*
	mv coding_computational_recruiting.zip release/

.PHONY: default compile release