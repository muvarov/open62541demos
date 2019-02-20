
OPCUA ?=  /opt/Linaro/xdp/open62541-install
OPCUA_SRC ?= /opt/Linaro/xdp/open62541.git
CF=pkg-config --cflags ${OPCUA}/lib/pkgconfig/open62541.pc
LD=pkg-config --libs ${OPCUA}/lib/pkgconfig/open62541.pc
LWIP_SRC ?= "/opt/Linaro/xdp/lwip.git/src"
LWIP_FLAGS = "-I${LWIP_SRC}/include -I${LWIP_SRC}/../contrib/ports/unix/lib \
	-I${LWIP_SRC}/../contrib/ports/unix/port/include \
	-I/opt/Linaro/xdp/open62541.git/arch/posix"
IPXDP ?= /opt/Linaro/xdp/open62541.git/lwip

all:
	$(CC) -std=c99 client_async.c lwip_init.c \
		 `${CF}` `${LD}` ${LWIP_FLAGS} \
		-I${LWIP_SRC}/include \
		-I${LWIP_SRC}/../contrib/ports/unix/lib \
		-I${LWIP_SRC}/../contrib/ports/unix/port/include \
		-I${OPCUA_SRC}/arch/common \
		-I${IPXDP} \
		-L${IPXDP} -lipxdp \
		${CFLAGS} ${LDFLAGS} \
		-l open62541 -o client_async
	$(CC) -std=c99 server_ctt.c lwip_init.c \
		 `${CF}` `${LD}` ${LWIP_FLAGS} \
		-I${LWIP_SRC}/include \
		-I${LWIP_SRC}/../contrib/ports/unix/lib \
		-I${LWIP_SRC}/../contrib/ports/unix/port/include \
		-I${OPCUA_SRC}/arch/common \
		-I${IPXDP} \
		-L${IPXDP} -lipxdp \
		${CFLAGS} ${LDFLAGS} \
		-l open62541 -o server_ctt
ifneq ($(ARCH),arm)
	$(CC) -std=c99 server_sensors.c \
			lwip_init.c \
		 `${CF}` `${LD}` ${LWIP_FLAGS} \
		-I${LWIP_SRC}/include \
		-I${LWIP_SRC}/../contrib/ports/unix/lib \
		-I${LWIP_SRC}/../contrib/ports/unix/port/include \
		-I${OPCUA_SRC}/arch/common \
		-I${IPXDP} \
		-L${IPXDP} -lipxdp \
		${CFLAGS} ${LDFLAGS} \
		-l open62541 -o server_sensors \
		${CFLAGS} ${LDFLAGS} -l open62541 -lsensors -o server_sensors
endif

LWXPD_LIB:="/opt/Linaro/xdp/ipxdp.git/lwip" 
KSRC:="/opt/Linaro/xdp/linux.git"

check:
	echo LD_LIBRARY_PATH=.:$(KSRC)/tools/lib/bpf:${LWXPD_LIB} ./prog_name
