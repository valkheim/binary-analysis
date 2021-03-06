all: loader gadgets

loader:
	$(MAKE) -C loader

gadgets:
	$(MAKE) -C gadgets

.PHONY: loader gadgets
