INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
all:
	gcc -I$(INC) -L$(LIB) -o out main.c -lcrypto -ldl
clean:
	rm out