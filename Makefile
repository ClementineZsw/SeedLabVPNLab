all: 
	gcc -o vpnserver vpnserver.c -lssl -lcrypto -lcrypt
	gcc -o vpnclient vpnclient.c -lssl -lcrypto -lcrypt

clean: 
	rm tlsclient tlsserver vpnserver vpnclient vpnclient1
