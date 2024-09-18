TARGETS := iouring-test

.PHONY = $(TARGETS)

all: $(TARGETS)

iouring-test: %: %.c
	@gcc -Wall -g -O2 -D_GNU_SOURCE $< -luring -o $@

clean:
	@rm -rf $(TARGETS)
