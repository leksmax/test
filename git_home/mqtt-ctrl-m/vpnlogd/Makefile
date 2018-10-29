CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -g -I. -I../common -DMG_ENABLE_SSL=1 -DMG_ENABLE_DEBUG=1 -L../common

SRCS=vpnlogd.cpp
OBJS=$(SRCS:.cpp=.o)
TARGET=vpnlogd

CXXFLAGS+=$(ROOT_CFLAGS)

LDLIBS=-lmytool -levmongoose -lcurl -lssl -lev -lcrypto -lm

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS)
clean:
	$(RM) $(TARGET) $(OBJS)
.PHONY: all clean
