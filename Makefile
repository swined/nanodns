build:
	gcc -Werror -Wall *.c -o nanodns
install:
	cp -f nanodns /usr/local/bin
	cp -f nanodns.init /etc/init.d/nanodns
	insserv nanodns
