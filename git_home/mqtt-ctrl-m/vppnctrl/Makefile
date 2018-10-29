CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -g -I. -I../common -DMG_ENABLE_SSL=1 -DMG_ENABLE_DEBUG=1 -L../common

SRCS=main.cpp bird_conf.cpp common-ctrl.cpp ctrl-interface.cpp ctrl_server.cpp vpn_config.cpp ctrl_server_json.cpp 
OBJS=$(SRCS:.cpp=.o)
TARGET=vppnctrl

CXXFLAGS+=$(ROOT_CFLAGS)
LDLIBS=-lmytool -ltinctool -levmongoose -lev -lcurl -lssl -lpthread -lz -lcrypto -lm

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS)
clean:
	$(RM) $(TARGET) $(OBJS)
.PHONY: all clean
