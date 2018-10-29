
TARGET  := vpnperf

SOURCES := main.c rpcd.c perf.c ping.c utils.c cjson.c
OBJS    := $(SOURCES:.c=.o)

LDFLAGS += -lm
IFLAGS += -I. 
CFLAGS += -Os -Wall -Wno-unused-result

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
