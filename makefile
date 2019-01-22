
CC = gcc
all: dissector jsmn jsontest compile
jsmn: jsmn.c 
	${CC}   jsmn.c -o jsmn.o -c
jsontest: jsontest.c
	${CC} jsontest.c -o jsontest.o -c
dissector: jsontest.c jsmn.c
	${CC} -o dissector jsontest.c jsmn.c
compile: dissector
	./dissector
