default:
ifdef name
	@cd challenge; \
		mkdir -p ../release/crypto_$(name); \
		sage -python3 generate.py; \
		python3 source.py; \
		cp output.txt ../htb/; \
	 	cp source.py output.txt ../release/crypto_$(name);

	@cd release; \
	 	zip -9 -r ./crypto_$(name).zip ./crypto_$(name); \
		unzip -l ./crypto_$(name).zip;
		
	@echo [+] Challenge was built successfully.
else
	@echo [-] Please define the challenge name. For example, \"make name=cool_chall_name\"
endif

flag:
	@echo [+] Flag : $$(cd challenge; python3 -c 'from secret import FLAG; print(FLAG);')

solver:
	@echo [+] Running solver
	@echo $$(cd challenge ; sage -python3 ../htb/solver.py)
	@find ./ -name "*.sage.py" -type f -delete

test: clean default flag solver

clean:
	@rm -rf release/*
	@rm -rf challenge/secret.py
	@find . -name "*.sage.py" -type f -delete
	@echo [+] Challenge release deleted successfully.
