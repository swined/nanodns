build:
	gcc -Werror -Wall *.c -o nanodns
install:
	cp nanodns /usr/local/bin
	cp nanodns.init /etc/init.d/nanodns
	insserv nanodns
