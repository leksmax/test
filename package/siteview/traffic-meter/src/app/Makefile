
TARGET	:= traffic_meter
SOURCES := main.c utils.c
OBJS 	:= $(SOURCES:.c=.o)

CFLAGS  += -Os
LDFLAGS += -lshared
IFLAGS  += -I./

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $< 

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
