
TARGET 	:= libevhtp.a
SOURCES := evhtp.c numtoa.c parser.c sslutils.c thread.c
OBJS 	:= $(SOURCES:.c=.o)

CFLAGS += -I./include -DEVHTP_SYS_ARCH=32

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) -rcs $@ $^

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $< 

clean:
	rm -f $(OBJS) $(TARGET) 

.PHONY: clean all
