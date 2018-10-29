bindir ?= bin/

HAVE_DNS_REPORT = 0
HAVE_PUBLICWHITELIST = 0
HAVE_LOCAL_VPN_CONFIG = 1

STATIC_LIB = 
#DYNAMIC_LIB = libdevice.so
TARGETS = vppnconfig

SRC = $(wildcard *.c)
INCS = $(wildcard *.h)
OBJS = $(SRC:%.c=%.o)
DEPS = $(OBJS:%.o=%.d)

INC_PATH = -I.
LD_PATH = 
#LD_LIBS = -lpthread -lrt
#LD_LIBS = -lm -lgnutls -lgcrypt
LD_LIBS = -lm -lz -lpthread

LD_FLAGS = -g 
LD_FLAGS += $(CFLAGS)
AR_FLAGS = rs
C_FLAGS = -Wall -fPIC -DHAVE_DNS_REPORT=$(HAVE_DNS_REPORT) -DHAVE_PUBLICWHITELIST=$(HAVE_PUBLICWHITELIST) -DHAVE_LOCAL_VPN_CONFIG=$(HAVE_LOCAL_VPN_CONFIG)
C_FLAGS += $(CFLAGS)
RM = rm -f

all : $(TARGETS)

all : $(TARGETS)
$(TARGETS) : $(OBJS)
	$(CC) $(LD_FLAGS)  $^ $(LD_LIBS) -o $@

%.d : %.c
	$(CC) $(INC_PATH) -MM -MD $(C_FLAGS) $< -o $@

%.o : %.c
	$(CC) $(C_FLAGS) $(INC_PATH) -c $< -o $@

clean:
	$(RM) $(OBJS) $(TARGETS) $(DEPS)

install:
	mkdir -p $(bindir)
	cp $(TARGETS) $(bindir)

sinclude $(DEPS)
#clean_src:
#	$(RM) $(SRC)
#depend:
#	for i in $(OBJS)
#	do
#	gcc -MM $(i) > $(i:%.o=%.d)
#	done
.PHONY : all clean install clean
