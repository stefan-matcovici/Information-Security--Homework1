INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
all:
	gcc -I$(INC) -L$(LIB) -o key-manager key-manager.c -lcrypto -ldl
	gcc -I$(INC) -L$(LIB) -o a a.c -lcrypto -ldl
	gcc -I$(INC) -L$(LIB) -o b b.c -lcrypto -ldl