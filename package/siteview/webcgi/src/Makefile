
TARGET  := web-cgi
SOURCES := web.c network.c utils.c cjson.c
OBJS    := $(SOURCES:.c=.o)

LDFLAGS += -lm -luci
IFLAGS += -I. 
CFLAGS += -Os -Wall

all: $(TARGET)
	@echo " cgi."
	@ln -sf /usr/sbin/web-cgi network.cgi
	@echo " cli."
	@ln -sf /usr/sbin/web-cgi network.cli

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	
.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
