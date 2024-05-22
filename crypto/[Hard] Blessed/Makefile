default:
ifdef name
	@cd challenge; \
		mkdir -p ../release/crypto_$(name); \
	 	cp server.py ../release/crypto_$(name);

	@cd release; \
	 	zip -9 -r ./crypto_$(name).zip ./crypto_$(name); \
		unzip -l ./crypto_$(name).zip;
		
	@echo [+] Challenge was built successfully.
else
	@echo [-] Please define the challenge name. For example, \"make name=cool_chall_name\"
endif

flag:
	@echo [+] Flag : $$(cd challenge; python3 -c 'print(open("flag.txt").read())')

solver:
	@echo [+] Running solver
	@echo $$(cd htb; sage -python3 solver.py)
	@find ./ -name "*.sage.py" -type f -delete

solver_remote:
	@echo [+] Running remote solver
	./build-docker.sh
	@echo $$(sage -python3 htb/solver.py localhost:1337)

test: clean default flag solver solver_remote

clean:
	@rm -rf release/*
	@find . -name "*.sage.py" -type f -delete
	@echo [+] Challenge release deleted successfully.
