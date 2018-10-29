CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -g -I. -I../common -DMG_ENABLE_SSL=1 -DMG_ENABLE_DEBUG=1 -L../common

SRCS=vpnctrl.cpp process-input.cpp input-param.cpp
OBJS=$(SRCS:.cpp=.o)
TARGET=vpnctrl.cgi

LDLIBS=-lmytool -levmongoose -lev -lcurl -lssl -lcrypto -lm -lz

CXXFLAGS+=$(ROOT_CFLAGS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS)
clean:
	$(RM) $(TARGET) $(OBJS)
.PHONY: all clean
