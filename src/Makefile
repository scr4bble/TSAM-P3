CC = gcc
CFLAGS = -std=gnu11 -O2 -g -Wall -Wextra -Wformat=2 $(shell pkg-config glib-2.0 openssl --cflags)

SERVER_PORT := 12345

# if "/labs/tsam15/my_port" exists
ifneq (,$(wildcard /labs/tsam15/my_port))
	SERVER_PORT := $(/labs/tsam15/my_port)
endif

.DEFAULT: all
.PHONY: all post clean run-server run-client zip


all: chatd chat

chat: chat.o getpasswd.o chat_common.o
	$(CC) $(CFLAGS) -o $@ $^ -lreadline $(shell pkg-config glib-2.0 openssl --libs)

chatd: chatd.o chat_common.o
	$(CC) $(CFLAGS) -o $@ $^ $(shell pkg-config glib-2.0 openssl --libs) -lm

clean:
	rm -f *.o *~

distclean: clean
	rm -f chatd chat

run-server:
	./chatd $(SERVER_PORT)

run-client:
	./chat 127.0.0.1 $(SERVER_PORT)

zip:
	cd ..; zip chat.zip README src/*.c src/Makefile AUTHORS
