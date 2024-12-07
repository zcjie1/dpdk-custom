#ifndef __ZCIO_H__
#define __ZCIO_H__

#include <stdatomic.h>
#include <sys/un.h>
#include <rte_memory.h>
#include <rte_ring.h>
#include "utils.h"
#include "parse_param.h"

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