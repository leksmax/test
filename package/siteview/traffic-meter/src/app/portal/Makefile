
PROJ_DIR   := $(shell pwd)

TARGET     := portal
SOURCES    := httpd.c ipfw.c
OBJS       := $(SOURCES:.c=.o)

LDFLAGS += -levhtp -levent -levent_openssl -lssl -lcrypto -lpthread -lm -L$(PROJ_DIR)/libevhtp
IFLAGS  += -I$(PROJ_DIR) -I$(PROJ_DIR)/libevhtp/include
CFLAGS  += -Os -Wall -Wno-unused-result

all: libevhtp $(TARGET) 

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	$(RM) -r *.o $(TARGET)

libevhtp:
	make -C $(PROJ_DIR)/libevhtp

libevhtp_clean:
	make -C $(PROJ_DIR)/libevhtp clean

.PHONY: clean libevhtp libevhtp_clean
