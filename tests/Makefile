TARGETS := iouring-test udpsock

.PHONY = $(TARGETS)

all: $(TARGETS)

iouring-test: %: %.c
	@gcc -Wall -g -O2 -D_GNU_SOURCE $< -luring -o $@

udpsock: %: %.c
	@gcc -Wall -g -O2 -D_GNU_SOURCE $< -lpthread -o $@

clean:
	@rm -rf $(TARGETS)
