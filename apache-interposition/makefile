all: apache_hook.so backup_apache_hook.so test.o
apache_hook.so: apache_hook.c
	gcc -Wall -fPIC -shared `pkg-config --cflags glib-2.0` apache_hook.c -o apache_hook.so -ldl -lpthread `pkg-config --libs glib-2.0`

backup_apache_hook.so: backup_apache_hook.c
	gcc -Wall -fPIC -shared `pkg-config --cflags glib-2.0` backup_apache_hook.c -o backup_apache_hook.so -ldl -lpthread `pkg-config --libs glib-2.0`

test.o: test.c
	gcc test.c -o test.o

clean:
	rm apache_hook.so

