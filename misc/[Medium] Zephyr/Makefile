default: release

release:
	cp -r challenge/ misc_zephyr/
	zip -9 -r misc_zephyr.zip misc_zephyr/

	rm -rf misc_zephyr
	rm -f release/*

	mv misc_zephyr.zip release/

.PHONY: default release