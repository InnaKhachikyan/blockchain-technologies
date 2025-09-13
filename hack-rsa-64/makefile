

all:
	gcc encrypt_rsa_64.c -o encrypt_rsa_64 -I/usr/local/include -L/usr/local/lib -ltomcrypt -ltommath -lm
	gcc hack_rsa_64.c -o hack_rsa -lm

test:
	./encrypt_rsa_64
	./hack_rsa
