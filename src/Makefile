TOOL_NAME       := dqdk
XDP_TARGETS     := bpf/forwarder.bpf
# BPF_SKEL_TARGETS:= bpf/forwarder.bpf
USER_TARGETS    := dqdk
EXTRA_USER_DEPS := bpf/forwarder.skel.h tcpip/* dlog.h dqdk-blk.h dqdk-sys.h dqdk-controller.h dqdk.h tristan.h ctypes.h
USER_EXTRA_C    := dqdk-blk.c
TEST_FILE       := 
SCRIPTS_FILES   := ../scripts/mlx5-rx-dbg.sh ../scripts/mlx5-optimize.sh ../tristan-daq.sh
LIB_DIR          = ../xdp-tools/lib
USER_LIBS       := -lpthread -lnuma -lm -luring
MAN_PAGE        :=
SCRIPTSDIR      := /usr/local/sbin
USER_DEFINES    += -D_GNU_SOURCE -I$(realpath .) -O3 -g -march=native
CFLAGS          += $(USER_DEFINES)
BPF_CFLAGS      += -I$(realpath .)

include $(LIB_DIR)/common.mk

bpf/forwarder.skel.h: bpf/forwarder.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< name $(notdir ${@:.skel.h=}) > $@


.PHONY: uninstall
uninstall:
	[ -f /usr/local/sbin/dqdk ] && rm /usr/local/sbin/dqdk
	[ -f /usr/local/lib/bpf/forwarder.bpf.o ] && rm /usr/local/lib/bpf/forwarder.bpf.o
	[ -f /usr/local/sbin/mlx5-rx-dbg.sh ] && rm /usr/local/sbin/mlx5-rx-dbg.sh
	[ -f /usr/local/sbin/mlx5-optimize.sh ] && rm /usr/local/sbin/mlx5-optimize.sh
	[ -f /usr/local/sbin/tristan-daq.sh ] && rm /usr/local/sbin/tristan-daq.sh
