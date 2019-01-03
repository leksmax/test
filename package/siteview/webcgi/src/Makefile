
TARGET  := web-cgi
SOURCES := main.c session.c servlet.c plugin.c upload.c cjson.c utils.c
SOURCES += auth.c network.c wireless.c vlan.c firewall.c system.c services.c traffic_meter.c
OBJS    := $(SOURCES:.c=.o)

LDFLAGS += -lm -luci -ldl
IFLAGS += -I. 
CFLAGS += -Os -Wall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
