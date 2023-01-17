SRCTREE := $(src)/../../..

CFLAGS += -Wall -Werror -Wno-stringop-overread
CFLAGS += -I$(SRCTREE)/tools/lib
CFLAGS += -I$(SRCTREE)/tools/lib/bpf
CFLAGS += -g 
CFLAGS += -I$(abspath $(CURDIR))/$(SRCTREE)/usr/include

LDLIBS += -L$(objtree)/gtests/lib/libbpf
LDLIBS += -static -lbpf -lz -lelf -lcap -lpthread -lm

TARGETS = pspping psp_key_benchmark

all: $(TARGETS)
