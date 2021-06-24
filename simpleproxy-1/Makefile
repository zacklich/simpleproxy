
all : webproxy
	echo done


webproxy : webproxy.o
	gcc -g -pthread -o webproxy webproxy.o

webproxy.o : webproxy.c queues.h
	gcc -g -c -Wall -Werror -o webproxy.o webproxy.c



clean :
	rm -f webproxy webproxy.o cache/page_*

