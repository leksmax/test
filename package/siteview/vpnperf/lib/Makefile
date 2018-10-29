CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -g -I. -fPIC
SRCS=vpnperf_client.c
OBJS=$(SRCS:.c=.o)
TARGET=libvpnperf_client.so

LDLIBS=-lm

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $^

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS)
clean:
	$(RM) $(TARGET) $(OBJS)
.PHONY: all clean
