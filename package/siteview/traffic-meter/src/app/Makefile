
TARGET	:= traffic_meter
SOURCES := main.c utils.c
OBJS 	:= $(SOURCES:.c=.o)

CFLAGS  += -Os -pipe
LDFLAGS += -lm
IFLAGS  += -I./

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ -fpic $(CFLAGS) $(IFLAGS) $< 

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean all
