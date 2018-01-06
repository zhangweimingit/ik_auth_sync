TARGET=ik_auth_sync
OBJS=main.o auth_config.o client.o auth_message.o

CPPFLAGS=-DNDEBUG $(EXTRA_CPPFLAGS)
CFLAGS=-Wall $(EXTRA_CFLAGS)
CXXFLAGS=-std=c++0x -g -Wall -Werror $(EXTRA_CXXFLAGS)
LDFLAGS=$(EXTRA_LDFLAGS) \
	-lpthread -lboost_program_options -lboost_system -lcrypto

.PHONY: all clean test

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJS)
	$(MAKE) -C test $@

test:
	$(MAKE) -C test

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)
