TARGET=ik_auth_sync
OBJS=main.o sync_config.o socket.o sync_client.o \
	event_poll.o sync_msg.o thread.o kernel_event.o

CPPFLAGS=-DNDEBUG $(EXTRA_CPPFLAGS)
CFLAGS=-Wall $(EXTRA_CFLAGS)
CXXFLAGS=-std=c++0x -g -Wall -Werror $(EXTRA_CXXFLAGS)
LDFLAGS=$(EXTRA_LDFLAGS) \
	-lpthread -lboost_program_options

.PHONY: all clean test

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJS)
	$(MAKE) -C test $@

test:
	$(MAKE) -C test

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)
