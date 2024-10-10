#ifndef __ZCIO_H__
#define __ZCIO_H__

#include <sys/un.h>
#include <rte_memory.h>
#include <rte_ring.h>
#include "utils.h"
#include "fd_man.h"

#define MAX_RECONNECT 8

enum zcio_socket_type {
	TYPE_CLIENT_2_SERVER,
	TYPE_SERVER_2_CLIENT,
	TYPE_CLIENT_2_MEMCTL,
	TYPE_SERVER_LISTENER,
	TYPE_NUM
};

struct zcio_socket {
	pthread_mutex_t mutex;
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

struct zcio_queue {
	struct zcio_socket *sock;
	struct rte_ring *ring; // rte_ring_create'd
	uint64_t packet_num;
	uint64_t packet_bytes;
};

enum zcio_msg_type {
	ZCIO_MSG_MAGIC = 8,
	ZCIO_MSG_PACKET,
	ZCIO_MSG_NUM
};

#define ZCIO_MAX_BURST 32
struct pkt_info {
	uint16_t pkt_num;
	uint64_t host_start_addr[ZCIO_MAX_BURST];
} __rte_packed;

struct zcio_msg {
	enum zcio_msg_type type;
	union {
		struct pkt_info packets;
	}payload;
} __rte_packed;

struct pmd_internal {
    bool server;
	rte_atomic16_t attched; // server 和 client 已连接
    rte_atomic16_t started; // 设备已启动
    char *server_iface; // rte_malloc'd
    char *memctl_iface; // rte_malloc'd
	struct zcio_socket unix_sock[TYPE_NUM];
	struct meminfo host_mem;
	struct meminfo guest_mem;
	struct zcio_queue rx_queue;
	struct zcio_queue tx_queue;
};

#endif // !__ZCIO_H__