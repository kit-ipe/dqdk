TOOL_NAME       := dqdk
XDP_TARGETS     := bpf/forwarder.bpf
BPF_SKEL_TARGETS:= bpf/forwarder.bpf
USER_TARGETS    := dqdk
EXTRA_USER_DEPS := bpf/forwarder.skel.h tcpip/*.h dlog.h dqdk-blk.h dqdk-sys.h dqdk-mem.h dqdk-async-processor.h dqdk.h dqdk-controller.h tristan.h ctypes.h ds/*
USER_EXTRA_C    := ds/*.c tcpip/*.c dqdk-blk.c dqdk-sys.c dqdk-mem.c dqdk-async-processor.c dqdk-controller.c tristan.c
TEST_FILE       := 
SCRIPTS_FILES   := ../scripts/mlx5-rx-dbg.sh ../scripts/mlx5-optimize.sh ../tristan-daq.sh ../tristan-daq-virtio.sh ../scripts/virtio-optimize.sh ../scripts/virtio-rx-dbg.sh ../scripts/veth-rx-dbg.sh ../tristan-daq-podman-veth.sh ../tristan-daq-podman-host.sh
LIB_DIR          = ../xdp-tools/lib
USER_LIBS       := -lpthread -lnuma -lm -luring
MAN_PAGE        :=
SCRIPTSDIR      := /usr/local/sbin
USER_DEFINES    += -D_GNU_SOURCE -I$(realpath .) -march=native -O3 -g
CFLAGS          += $(USER_DEFINES)
BPF_CFLAGS      += -I$(realpath .)

include $(LIB_DIR)/common.mk

.PHONY: uninstall
uninstall:
	[ -f $(DESTDIR)/usr/local/sbin/dqdk ] && rm $(DESTDIR)/usr/local/sbin/dqdk
	[ -f $(DESTDIR)/usr/local/lib/bpf/forwarder.bpf.o ] && rm $(DESTDIR)/usr/local/lib/bpf/forwarder.bpf.o
	[ -f $(DESTDIR)/usr/local/sbin/mlx5-rx-dbg.sh ] && rm $(DESTDIR)/usr/local/sbin/mlx5-rx-dbg.sh
	[ -f $(DESTDIR)/usr/local/sbin/mlx5-optimize.sh ] && rm $(DESTDIR)/usr/local/sbin/mlx5-optimize.sh
	[ -f $(DESTDIR)/usr/local/sbin/tristan-daq.sh ] && rm $(DESTDIR)/usr/local/sbin/tristan-daq.sh
	[ -f $(DESTDIR)/usr/local/sbin/virtio-optimize.sh ] && rm $(DESTDIR)/usr/local/sbin/virtio-optimize.sh
	[ -f $(DESTDIR)/usr/local/sbin/virtio-rx-dbg.sh ] && rm $(DESTDIR)/usr/local/sbin/virtio-rx-dbg.sh
	[ -f $(DESTDIR)/usr/local/sbin/tristan-daq-podman-host.sh ] && rm $(DESTDIR)/usr/local/sbin/tristan-daq-podman-host.sh
	[ -f $(DESTDIR)/usr/local/sbin/tristan-daq-podman-veth.sh ] && rm $(DESTDIR)/usr/local/sbin/tristan-daq-podman-veth.sh
	[ -f $(DESTDIR)/usr/local/sbin/tristan-daq-virtio.sh ] && rm $(DESTDIR)/usr/local/sbin/tristan-daq-virtio.sh
	[ -f $(DESTDIR)/usr/local/sbin/veth-rx-dbg.sh ] && rm $(DESTDIR)/usr/local/sbin/veth-rx-dbg.sh
