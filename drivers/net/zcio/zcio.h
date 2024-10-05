#ifndef __ZCIO_H__
#define __ZCIO_H__

#include <sys/un.h>
#include <rte_memory.h>
#include "fd_man.h"

RTE_LOG_REGISTER_DEFAULT(zcio_logtype, INFO);

#define ZCIO_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, zcio_logtype, __VA_ARGS__)

#define ETH_ZCIO_SERVER_ARG		        "server"
#define ETH_ZCIO_SERVER_IFACE_ARG       "server-iface"
#define ETH_ZCIO_QUEUES_ARG		        "queues"
#define ETH_ZCIO_MEMCTL_IFACE_ARG		"memctl-iface"

enum zcio_socket_type {
	TYPE_CLIENT_2_SERVER,
	TYPE_SERVER_2_CLIENT,
	TYPE_SERVER_LISTENER,
	TYPE_CLIENT_2_MEMCTL,
	TYPE_NUM
};

struct zcio_socket {
	int sock_fd;
	struct sockaddr_un un;
};

struct pmd_internal {
    bool server;
	rte_atomic16_t attched; // server 和 client 已连接
    rte_atomic16_t started; // 设备已启动
    char *server_iface; // rte_malloc'd
    char *memctl_iface; // rte_malloc'd
	struct zcio_socket unix_sock[TYPE_NUM];
	struct fdset fdset;
};

#endif // !__ZCIO_H__