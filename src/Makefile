TOOL_NAME       := dqdk
XDP_TARGETS     := bpf/forwarder.bpf
# BPF_SKEL_TARGETS:= bpf/forwarder.bpf
USER_TARGETS    := dqdk
EXTRA_USER_DEPS := bpf/forwarder.skel.h tcpip/* dlog.h dqdk-blk.h dqdk-sys.h dqdk.h tristan.h
USER_EXTRA_C    := dqdk-blk.c
TEST_FILE       := 

LIB_DIR          = ../xdp-tools/lib
USER_LIBS       := -lpthread -lnuma -lm -luring
MAN_PAGE        :=

USER_DEFINES    += -D_GNU_SOURCE -I$(realpath .)
CFLAGS          += -I$(realpath ../xdp-tools/headers/) -I$(realpath ../xdp-tools/lib/libbpf/src) -O3 $(USER_DEFINES)
BPF_CFLAGS      += -I$(realpath .)

include $(LIB_DIR)/common.mk

bpf/forwarder.skel.h: bpf/forwarder.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< name $(notdir ${@:.skel.h=}) > $@
