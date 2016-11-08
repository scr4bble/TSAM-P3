.DEFAULT: all
.PHONY: all post clean distclean zip run

all:
	$(MAKE) -C src

clean:
	$(MAKE) clean -C src

distclean: clean
	$(MAKE) distclean -C src

run:
	$(MAKE) run -C src

post:
	$(MAKE) post -C src

zip:
	$(MAKE) zip -C src


chat:
	$(MAKE) chat -C src

chatd:
	$(MAKE) chatd -C src

run-server:
	$(MAKE) run-server -C src

run-client:
	$(MAKE) run-client -C src

