#ifndef __ZCIO_H__
#define __ZCIO_H__

#include <stdatomic.h>
#include <sys/un.h>
#include <rte_memory.h>
#include <rte_ring.h>
#include "utils.h"
#include "parse_param.h"

// #define MAX_RECONNECT 8
// #define MAX_RX_BURST_NUM 32767

// enum zcio_socket_type {
// 	TYPE_CLIENT_2_SERVER,
// 	TYPE_SERVER_2_CLIENT,
// 	TYPE_CLIENT_2_MEMCTL,
// 	TYPE_SERVER_LISTENER,
// 	TYPE_NUM
// };

// struct zcio_socket {
// 	pthread_mutex_t mutex;
// 	int sock_fd;
// 	struct sockaddr_un un;
// };

// struct memory_region {
// 	uint64_t satrt_addr;
// 	uint64_t memory_size;
// 	uint64_t mmap_offset;
// };

// #define MAX_FD_NUM 64
// #define MAX_REGION_NUM 64
// struct meminfo {
// 	int region_nr;
// 	int fds[MAX_FD_NUM];
//     struct memory_region regions[MAX_REGION_NUM];
// 	uint64_t invalid_mask; // 标注未成功获取或mmap的fd
// };

// #define MAX_NAME_LEN 64
// #define MAX_FREE_QUEUE_SIZE	64
// struct zcio_queue {
// 	struct zcio_socket *sock;
// 	char *data_ring_name; // malloc'd
// 	char *free_ring_name; // malloc'd
// 	struct rte_ring *data_pkt_ring; // rte_ring_create'd
// 	struct rte_ring *free_pkt_ring; // rte_ring_create'd
// 	uint64_t packet_num;
// 	uint64_t packet_bytes;
// };

// enum zcio_msg_type {
// 	ZCIO_MSG_MAGIC = 4,
// 	ZCIO_MSG_DATA_PKT,
// 	ZCIO_MSG_REQUEST_PKT, // client -> server 请求分配数据包空间
// 	ZCIO_MSG_RESPONSE_PKT, // server -> client 响应分配数据包空间
// 	ZCIO_MSG_FREE_PKT, // client -> server 释放数据包空间
// 	ZCIO_MSG_NUM
// };

// #define ZCIO_MAX_BURST 32
// struct pkt_info {
// 	uint16_t pkt_num;
// 	uint64_t host_start_addr[ZCIO_MAX_BURST];
// } __rte_packed;

// struct zcio_msg {
// 	enum zcio_msg_type type;
// 	union {
// 		uint16_t pkt_num;
// 		struct pkt_info packets;
// 	}payload;
// } __rte_packed;

#define MAX_QUEUES_NUM 8
#define MAX_QUEUES_NAME_LEN 29
struct zcio_info {
	atomic_flag lock; // 互斥锁
	bool valid_info; // zcio_info 是否有效, 由 server 端设置
	bool attached; // server 和 client 已连接，由 client 端设置
	uint64_t rxq_mask;
	uint64_t txq_mask;
	char rxq_name[MAX_QUEUES_NUM][MAX_QUEUES_NAME_LEN];
	char txq_name[MAX_QUEUES_NUM][MAX_QUEUES_NAME_LEN];
};

struct zcio_ring {
	uint8_t qid;
	struct pmd_internal *internal;
	struct rte_ring *ring; // rte_ring_create'd
};

struct zcio_queue {
	uint64_t *queues_mask;
	uint64_t pkt_num[MAX_QUEUES_NUM];
	uint64_t bytes_num[MAX_QUEUES_NUM];
	struct zcio_ring zring[MAX_QUEUES_NUM]; 
};

struct pmd_internal {
    bool server;
	bool enable_rx_csum;
	bool enable_tx_csum;
    rte_atomic16_t started;
	uint16_t max_queues;
	struct rte_mempool *mempool;
    char *info_name; // rte_malloc'd
	const struct rte_memzone *info_zone;
	struct zcio_info *info;
	struct zcio_queue rx_queue;
	struct zcio_queue tx_queue;
};

#endif // !__ZCIO_H__