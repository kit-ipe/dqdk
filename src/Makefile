TOOL_NAME       := dqdk
XDP_TARGETS     := bpf/xsk.bpf
USER_TARGETS    := dqdk
EXTRA_USER_DEPS := tcpip/* dlog.h dqdk.h tristan.h
TEST_FILE       := 

LIB_DIR          = $(abspath ../xdp-tools/lib)
USER_LIBS       := -lpthread -lnuma -lm
MAN_PAGE        :=

USER_DEFINES    += -D_GNU_SOURCE
CFLAGS          += -I$(realpath .) -O3 -Wno-maybe-uninitialized $(USER_DEFINES)
BPF_CFLAGS      += -I$(realpath .)

include $(LIB_DIR)/common.mk
