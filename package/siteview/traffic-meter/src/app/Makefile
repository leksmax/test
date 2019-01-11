
TARGET	:= traffic_meter
SOURCES := main.c utils.c
OBJS 	:= $(SOURCES:.c=.o)

CFLAGS  += -Os
LDFLAGS += -lshared
IFLAGS  += -I./

all: $(TARGET) portal

portal:
	$(MAKE) -C ./portal

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $< 

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean portal
