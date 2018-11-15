CFLAGS = `pkg-config --cflags glib-2.0` 
LDLIBS = `pkg-config --libs glib-2.0`

all: wget_hook_tcp.so

wget_hook_tcp.so: wget_hook_tcp.c
	gcc $(CFLAGS) $(LDLIBS) -Wall -fPIC -shared wget_hook_tcp.c -o wget_hook_tcp.so -lglib-2.0 -ldl -lpthread

command:
	echo "USE sudo LD_PRELOAD=./wget_hook.so wget https://www.google.com -d --no-hsts"

clean:
	rm wget_hook_tcp.so
