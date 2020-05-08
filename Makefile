mypack: main.c hash.c netflow-table.c
	gcc -g -o mypack main.c netflow-table.c hash.c -lpthread -lrt -I.
