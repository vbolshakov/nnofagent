CC = gcc
TARGET_CFLAGS += -ggdb3

FILES = agent.c ofmsgbuf.c openflow.c openflow13.c flows.c meters.c groups.c

nnofagent: $(FILES)
			$(CC) -g -w -o $@ $(FILES)


