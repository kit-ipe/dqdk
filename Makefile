.PHONY: dqdk dqdk-install dqdk-clean xdploader xdploader-install xdploader-clean install clean all

all: dqdk xdploader

dqdk:
	@$(MAKE) -C src

dqdk-install: dqdk
	@$(MAKE) -C src install

dqdk-clean:
	@$(MAKE) -C src clean

xdploader:
	@$(MAKE) -C xdp-tools/xdp-loader

xdploader-install: xdploader
	@$(MAKE) -C xdp-tools/xdp-loader install

xdploader-clean:
	@$(MAKE) -C xdp-tools/xdp-loader clean

install: xdploader-install dqdk-install

clean: xdploader-clean dqdk-clean
