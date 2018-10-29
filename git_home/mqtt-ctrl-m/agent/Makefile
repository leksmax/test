CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -g -I. -I../common -DMG_ENABLE_SSL=1 -DMG_ENABLE_DEBUG=1 -L../common

SRCS1=mqtt-agent.cpp
OBJS1=$(SRCS1:.cpp=.o)
SRCS2=monitor-agent.cpp
OBJS2=$(SRCS2:.cpp=.o)
SRCS3=tinc_dump.cpp
OBJS3=$(SRCS3:.cpp=.o)
SRCS4=vpncloud_agent.cpp
OBJS4=$(SRCS4:.cpp=.o)
TARGET=mqtt-agent monitor-agent tinc_dump vpncloud_agent

CXXFLAGS+=$(ROOT_CFLAGS)

LDLIBS=-lmytool -ltinctool -levmongoose -lev -lcurl -lssl -lcrypto -lm

all: mqtt-agent monitor-agent tinc_dump vpncloud_agent

mqtt-agent: $(OBJS1)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

monitor-agent: $(OBJS2)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

tinc_dump: $(OBJS3)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

vpncloud_agent: $(OBJS4)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS)
clean:
	$(RM) mqtt-agent monitor-agent tinc_dump vpncloud_agent $(OBJS1) $(OBJS2) $(OBJS3) $(OBJS4)
.PHONY: all clean
