
BIN := config
LIB := libconfig.so
TARGET := $(BIN) $(LIB)

BIN_SOURCES := cli.c
LIB_SOURCES := config.c

BIN_OBJS := $(BIN_SOURCES:.c=.o)
LIB_OBJS := $(LIB_SOURCES:.c=.o)
OBJS     := $(BIN_OBJS) $(LIB_OBJS)

LDFLAGS += -luci 
IFLAGS += -I. 
CFLAGS += -Os -Wall

all: $(TARGET)

$(BIN): $(LIB) $(BIN_OBJS)
	 $(CC) -o $@ $^ $(LDFLAGS) -L. -lconfig

$(BIN_OBJS): $(BIN_SOURCES)
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

$(LIB): $(LIB_OBJS)
	$(CC) -s -shared -o $@ $(LIB_OBJS) $(LDFLAGS)
	
$(LIB_OBJS): $(LIB_SOURCES)
	$(CC) -c -o $@ -fpic $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
