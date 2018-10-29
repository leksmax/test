CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -g -I. -DMG_ENABLE_SSL=1 -DMG_ENABLE_DEBUG=1

SRCS=my-device.cpp system-config.cpp vpn_tool.cpp net_tool.cpp file_tool.cpp process_tool.cpp cJSON.cpp my_debug.cpp monitor_tool.cpp log_tool.cpp str_tool.cpp vpn_cloud.cpp udp_tool.cpp timer_tool.cpp compress_tool.cpp HttpClient.cpp uds_client.cpp
OBJS=$(SRCS:.cpp=.o)
TARGET=libmytool.a

LDLIBS=-levmongoose -lcurl -lssl -lev -lcrypto -lz -lm

CXXFLAGS+=$(ROOT_CFLAGS)

all: $(TARGET)

libmytool.a: $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS)
clean:
	$(RM) $(TARGET) $(OBJS)
.PHONY: all clean
