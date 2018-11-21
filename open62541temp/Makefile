all:
	$(CC) -std=c99 client_async.c ${CFLAGS} ${LDFLAGS} -l open62541 -o client_async
	$(CC) -std=c99 server_ctt.c ${CFLAGS} ${LDFLAGS} -l open62541 -o server_ctt
	$(CC) -std=c99 server_sensors.c ${CFLAGS} ${LDFLAGS} -l open62541 -lsensors -o server_sensors

