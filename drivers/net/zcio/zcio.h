#ifndef __ZCIO_H__
#define __ZCIO_H__

#include <sys/un.h>
#include <rte_memory.h>
#include "utils.h"
#include "fd_man.h"

RTE_LOG_REGISTER_DEFAULT(zcio_logtype, INFO);

#define ZCIO_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, zcio_logtype, __VA_ARGS__)

#define ETH_ZCIO_SERVER_ARG		        "server"
#define ETH_ZCIO_SERVER_IFACE_ARG       "server-iface"
#define ETH_ZCIO_QUEUES_ARG		        "queues"
#define ETH_ZCIO_MEMCTL_IFACE_ARG		"memctl-iface"

#define MAX_RECONNECT 8

enum zcio_socket_type {
	TYPE_CLIENT_2_SERVER,
	TYPE_SERVER_2_CLIENT,
	TYPE_CLIENT_2_MEMCTL,
	TYPE_SERVER_LISTENER,
	TYPE_NUM
};

struct zcio_socket {
	int sock_fd;
	struct sockaddr_un un;
};

struct memory_region {
	uint64_t satrt_addr;
	uint64_t memory_size;
	uint64_t mmap_offset;
};

#define MAX_FD_NUM 64
#define MAX_REGION_NUM 64
struct meminfo {
	int region_nr;
	int fds[MAX_FD_NUM];
    struct memory_region regions[MAX_REGION_NUM];
	uint64_t invalid_mask; // 标注未成功获取或mmap的fd
};

struct pmd_internal {
    bool server;
	rte_atomic16_t attched; // server 和 client 已连接
    rte_atomic16_t started; // 设备已启动
    char *server_iface; // rte_malloc'd
    char *memctl_iface; // rte_malloc'd
	struct zcio_socket unix_sock[TYPE_NUM];
	struct fdset fdset;
	struct meminfo host_mem;
	struct meminfo guest_mem;
};

#endif // !__ZCIO_H__