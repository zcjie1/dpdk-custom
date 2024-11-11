
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <rte_log.h>
#include <rte_bus_vdev.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <bus_vdev_driver.h>
#include <rte_net.h>

#include "zcio.h"

#if __INTELLISENSE__
#pragma diag_suppress 1094
#endif

RTE_LOG_REGISTER_DEFAULT(zcio_logtype, INFO);

#define ZCIO_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zcio_logtype, "ZCIO: "fmt, ##args)

#define ETH_ZCIO_SERVER_ARG		     "server"
#define ETH_ZCIO_INFO_NAME_ARG       "info-name"
#define ETH_ZCIO_QUEUES_ARG		     "queues"

static const char *valid_arguments[] = {
	ETH_ZCIO_SERVER_ARG,
    ETH_ZCIO_INFO_NAME_ARG,
    ETH_ZCIO_QUEUES_ARG,
	NULL
};

static struct rte_ether_addr base_eth_addr = {
	.addr_bytes = {
		0x5A,   /* Z */
		0x43,   /* C */
		0x49,   /* I */
		0x4F,   /* O */
		0x00,
		0x00
	}
};

static struct rte_eth_link pmd_link = {
    .link_speed = 10000,
    .link_duplex = RTE_ETH_LINK_FULL_DUPLEX,
    .link_status = RTE_ETH_LINK_DOWN
};

static int eth_dev_start(struct rte_eth_dev *eth_dev);
static int eth_dev_stop(struct rte_eth_dev *dev);
static int eth_dev_close(struct rte_eth_dev *dev);
static int eth_dev_configure(struct rte_eth_dev *dev);
static int eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info);
static int eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id, uint16_t nb_rx_desc, 
		unsigned int socket_id, const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mb_pool);
static int eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id, uint16_t nb_tx_desc, 
		   unsigned int socket_id, const struct rte_eth_txconf *tx_conf);
static int eth_tx_done_cleanup(void *txq, uint32_t free_cnt);
static int eth_link_update(struct rte_eth_dev *dev, int wait_to_complete);
static int eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
static int eth_stats_reset(struct rte_eth_dev *dev);
static int zcio_dev_priv_dump(struct rte_eth_dev *dev, FILE *f);


static int
zcio_start_server(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	
	ZCIO_LOG(INFO, "ZCIO server mode configure\n");
	info = rte_memzone_reserve(internal->info_name, sizeof(struct zcio_info), 0, RTE_MEMZONE_1GB);
	if(info == NULL)
		goto err;
	
	memset(info, 0, sizeof(struct zcio_info));
	internal->rx_queue.queues_mask = &info->rxq_mask;
	internal->tx_queue.queues_mask = &info->txq_mask;
	return 0;
 err:
	return -1;
}

static int
zcio_start_client(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	struct zcio_queue *rxq = &internal->rx_queue;
	struct zcio_queue *txq = &internal->tx_queue;
	
	ZCIO_LOG(INFO, "ZCIO client mode configure\n");
	info = rte_memzone_lookup(internal->info_name);
	while(info == NULL) {
		sleep(3);
		ZCIO_LOG(INFO, "retry to lookup zcio_info memzone %s\n", internal->info_name);
		info = rte_memzone_lookup(internal->info_name);
	}

	while(!info->valid_info) { sleep(3);} // 等待 zcio_info 有效位置位

	// 设置client的收发队列
	rxq->queues_mask = &info->txq_mask;
	txq->queues_mask = &info->rxq_mask;
	for(int i = 0; i < MAX_QUEUES_NUM; i++) {
		if(is_bit_set(*rxq->queues_mask, i)) {
			rxq->ring[i] = rte_ring_lookup(info->txq_name[i]);
			if(rxq->ring[i] == NULL) {
				ZCIO_LOG(ERR, "client rxq[%d] ring is NULL\n", i);
				goto err;
			}
				
		}
		if(is_bit_set(*txq->queues_mask, i)) {
			txq->ring[i] = rte_ring_lookup(info->rxq_name[i]);
			if(txq->ring[i] == NULL) {
				ZCIO_LOG(ERR, "client txq[%d] ring is NULL\n", i);
				goto err;
			}
				
		}
	}
	
	return 0;

 err:
	return -1;
}

static void
zcio_dev_csum_configure(struct rte_eth_dev *eth_dev)
{
	struct pmd_internal *internal = eth_dev->data->dev_private;
	const struct rte_eth_rxmode *rxmode = &eth_dev->data->dev_conf.rxmode;
	const struct rte_eth_txmode *txmode = &eth_dev->data->dev_conf.txmode;

	internal->enable_rx_csum = false;
	internal->enable_tx_csum = false;

	if ((rxmode->offloads &
			(RTE_ETH_RX_OFFLOAD_UDP_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM))) {
		ZCIO_LOG(INFO, "Rx csum will be done in SW, may impact performance.\n");
		internal->enable_rx_csum = true;
	}
	
	if (txmode->offloads &
			(RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM)) {
		ZCIO_LOG(INFO, "Tx csum will be done in SW, may impact performance.\n");
		internal->enable_tx_csum = true;
	}
	
}

static int
eth_dev_start(struct rte_eth_dev *eth_dev)
{
	struct pmd_internal *internal = eth_dev->data->dev_private;
	struct zcio_info *info = internal->info;
	uint16_t i;

	rte_atomic16_set(&internal->started, 1);
	
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		eth_dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	
	if(internal->server)
		internal->info->valid_info = true;
	else
		internal->info->attached = true;

	return 0;
}

static int
eth_dev_stop(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	uint16_t i;

	dev->data->dev_started = 0;
	rte_atomic16_set(&internal->started, 0);

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	
	if(!internal->server)
		info->attached = false;

	return 0;
}

static int
eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal;
	struct rte_mbuf *pkt;

	internal = dev->data->dev_private;
	if (!internal)
		return 0;
	
	eth_dev_stop(dev);

	// 清空 rx_ring 中的元素
	struct rte_ring *ring = internal->rx_queue.ring;
	while(rte_ring_dequeue(ring, (void **)&pkt) == 0) {
		rte_pktmbuf_free(pkt);
	}

	for(int i = 0; i < MAX_QUEUES_NUM; i++) {
		eth_rx_queue_release(dev, (uint16_t)i);
	}

	rte_free(dev->data->mac_addrs);
	rte_free(internal->info_name);
	rte_free(internal);

	dev->data->dev_private = NULL;

	return 0;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;

	// 设置校验和标志位
	zcio_dev_csum_configure(dev);

	if(internal->server) {
		return zcio_start_server(dev);
	}else {
		return zcio_start_client(dev);
	}
}

static int
eth_dev_info(struct rte_eth_dev *dev,
	     struct rte_eth_dev_info *dev_info)
{
	struct pmd_internal *internal;

	internal = dev->data->dev_private;
	if (internal == NULL) {
		ZCIO_LOG(ERR, "Invalid device specified\n");
		return -ENODEV;
	}

	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = dev->data->nb_rx_queues;
	dev_info->max_tx_queues = dev->data->nb_tx_queues;
	dev_info->min_rx_bufsize = 0;

	// dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	
	// dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
	// 	RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
	
	// dev_info->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
	// 	RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

	return 0;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		   uint16_t nb_rx_desc, unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool)
{
	static uint32_t rxq_count;
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	struct zcio_queue *vq = &internal->rx_queue;

	if(rx_queue_id >= internal->max_queues) {
		ZCIO_LOG(ERR, "invalid rx queue id %d\n", rx_queue_id);
		return -1;
	}

	internal->mempool = mb_pool;

	if(internal->server) {
		snprintf(info->rxq_name[rx_queue_id], MAX_QUEUES_NAME_LEN, "zcio_rxq%u", rxq_count++);
		vq->ring[rx_queue_id] = rte_ring_create(info->rxq_name[rx_queue_id], 
			nb_rx_desc, socket_id, RING_F_SP_ENQ |RING_F_SC_DEQ);
		set_bit(&info->rxq_mask, rx_queue_id);
	}else {
		if(is_bit_set(*vq->queues_mask, rx_queue_id)) {
			ZCIO_LOG(ERR, "zcio client do not support rxq%d\n", rx_queue_id);
			return -1;
		}
	}
		
	dev->data->rx_queues[rx_queue_id] = vq;

	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		   uint16_t nb_tx_desc __rte_unused, 
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	static uint32_t txq_count;
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	struct zcio_queue *vq = &internal->tx_queue;

	if(tx_queue_id >= internal->max_queues) {
		ZCIO_LOG(ERR, "invalid tx queue id %d\n", tx_queue_id);
		return -1;
	}

	if(internal->server) {
		snprintf(info->rxq_name[tx_queue_id], MAX_QUEUES_NAME_LEN, "zcio_txq%u", txq_count++);
		vq->ring[tx_queue_id] = rte_ring_create(info->rxq_name[tx_queue_id], 
			nb_tx_desc, socket_id, RING_F_SP_ENQ |RING_F_SC_DEQ);
		set_bit(&info->txq_mask, tx_queue_id);
	}else {
		if(is_bit_set(*vq->queues_mask, tx_queue_id)) {
			ZCIO_LOG(ERR, "zcio client do not support txq%d\n", tx_queue_id);
			return -1;
		}
	}
	
	dev->data->tx_queues[tx_queue_id] = vq;

	return 0;
}

static void
eth_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	struct zcio_queue *vq = &internal->rx_queue;

	lock_mutex(&info->lock);
	if(is_bit_set(*vq->queues_mask, qid)) {
		rte_ring_free(vq->ring[qid]);
		vq->ring[qid] = NULL;
		clear_bit(vq->queues_mask, qid);
	}
	unlock_mutex(&info->lock);
	
	return;
}

static void
eth_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_info *info = internal->info;
	struct zcio_queue *vq = &internal->tx_queue;

	lock_mutex(&info->lock);
	if(is_bit_set(*vq->queues_mask, qid)) {
		rte_ring_free(vq->ring[qid]);
		vq->ring[qid] = NULL;
		clear_bit(vq->queues_mask, qid);
	}
	unlock_mutex(&info->lock);
	
	return;
}

static int
eth_tx_done_cleanup(void *txq __rte_unused, uint32_t free_cnt __rte_unused)
{
	/**
	 * zcio does not hang onto mbuf, it transfer packets 
	 * without data copy
	 */
	return 0;
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
		int wait_to_complete __rte_unused)
{
	return 0;
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *rxq = &internal->rx_queue;
	struct zcio_queue *txq = &internal->tx_queue;

	uint64_t ipackets = 0; uint64_t ibytes = 0;
	uint64_t opackets = 0; uint64_t obytes = 0;

	// 收发队列数据统计
	for(int i = 0; i < MAX_QUEUES_NUM; i++) {
		if(is_bit_set(*rxq->queues_mask, i)) {
			ipackets += rxq->pkt_num[i];
			ibytes += rxq->bytes_num[i];
		}

		if(is_bit_set(*txq->queues_mask, i)) {
			opackets += txq->pkt_num[i];
			obytes += txq->bytes_num[i];
		}
	}
	
	stats->ipackets = ipackets;
	stats->opackets = opackets;
	stats->ibytes = ibytes;
	stats->obytes = obytes;

	return 0;
}

static int
eth_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *rxq = &internal->rx_queue;
	struct zcio_queue *txq = &internal->tx_queue;

	for(int i = 0; i < MAX_QUEUES_NUM; i++) {
		rxq->pkt_num[i] = 0;
		rxq->bytes_num[i] = 0;
		txq->pkt_num[i] = 0;
		txq->bytes_num[i] = 0;
	}
	

	return 0;
}

static int
zcio_dev_priv_dump(struct rte_eth_dev *dev __rte_unused, FILE *f)
{
	fprintf(f, "Dump pmd_internal info, but I am too lazy to code it.\n");
	fprintf(f, "Please refer to the zcio.h\n");
	return 0;
}

static const struct eth_dev_ops eth_zcio_ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_close = eth_dev_close,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_rx_queue_release,
	.tx_queue_release = eth_tx_queue_release,
	.tx_done_cleanup = eth_tx_done_cleanup,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
	.eth_dev_priv_dump = zcio_dev_priv_dump,
};

static void
zcio_dev_tx_sw_csum(struct rte_mbuf *mbuf)
{
	mbuf->ol_flags &= ~RTE_MBUF_F_TX_L4_MASK;
	mbuf->ol_flags |= RTE_MBUF_F_TX_L4_NO_CKSUM;
	return;
	
	uint32_t hdr_len;
	uint16_t csum = 0, csum_offset;

	switch (mbuf->ol_flags & RTE_MBUF_F_TX_L4_MASK) {
	case RTE_MBUF_F_TX_L4_NO_CKSUM:
		return;
	case RTE_MBUF_F_TX_TCP_CKSUM:
		csum_offset = offsetof(struct rte_tcp_hdr, cksum);
		break;
	case RTE_MBUF_F_TX_UDP_CKSUM:
		csum_offset = offsetof(struct rte_udp_hdr, dgram_cksum);
		break;
	default:
		/* Unsupported packet type. */
		return;
	}

	hdr_len = mbuf->l2_len + mbuf->l3_len;
	csum_offset += hdr_len;

	/* Prepare the pseudo-header checksum */
	if (rte_net_intel_cksum_prepare(mbuf) < 0)
		return;

	if (rte_raw_cksum_mbuf(mbuf, hdr_len, rte_pktmbuf_pkt_len(mbuf) - hdr_len, &csum) < 0)
		return;

	csum = ~csum;
	/* See RFC768 */
	if (unlikely((mbuf->packet_type & RTE_PTYPE_L4_UDP) && csum == 0))
		csum = 0xffff;

	if (rte_pktmbuf_data_len(mbuf) >= csum_offset + 1)
		*rte_pktmbuf_mtod_offset(mbuf, uint16_t *, csum_offset) = csum;

	mbuf->ol_flags &= ~RTE_MBUF_F_TX_L4_MASK;
	mbuf->ol_flags |= RTE_MBUF_F_TX_L4_NO_CKSUM;
}

static void
zcio_dev_rx_sw_csum(struct rte_mbuf *mbuf)
{
	mbuf->ol_flags &= ~RTE_MBUF_F_RX_L4_CKSUM_MASK;
	mbuf->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
	return;
	
	struct rte_net_hdr_lens hdr_lens;
	uint32_t ptype, hdr_len;
	uint16_t csum = 0, csum_offset;

	/* Return early if the L4 checksum was not offloaded */
	if ((mbuf->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) != RTE_MBUF_F_RX_L4_CKSUM_NONE)
		return;

	ptype = rte_net_get_ptype(mbuf, &hdr_lens, RTE_PTYPE_ALL_MASK);

	hdr_len = hdr_lens.l2_len + hdr_lens.l3_len;

	switch (ptype & RTE_PTYPE_L4_MASK) {
	case RTE_PTYPE_L4_TCP:
		csum_offset = offsetof(struct rte_tcp_hdr, cksum) + hdr_len;
		break;
	case RTE_PTYPE_L4_UDP:
		csum_offset = offsetof(struct rte_udp_hdr, dgram_cksum) + hdr_len;
		break;
	default:
		/* Unsupported packet type */
		return;
	}

	if (rte_raw_cksum_mbuf(mbuf, hdr_len, rte_pktmbuf_pkt_len(mbuf) - hdr_len, &csum) < 0)
		return;

	csum = ~csum;
	/* See RFC768 */
	if (unlikely((ptype & RTE_PTYPE_L4_UDP) && csum == 0))
		csum = 0xffff;

	if (rte_pktmbuf_data_len(mbuf) >= csum_offset + 1)
		*rte_pktmbuf_mtod_offset(mbuf, uint16_t *, csum_offset) = csum;

	mbuf->ol_flags &= ~RTE_MBUF_F_RX_L4_CKSUM_MASK;
	mbuf->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
}

static uint16_t
eth_zcio_server_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *rx_queue = q;
	struct pmd_internal *internal = container_of(rx_queue, struct pmd_internal, rx_queue);
	struct rte_ring *ring = rx_queue->data_pkt_ring;
	int ret = 0;
	
	if(rte_atomic16_read(&internal->attched) == 0)
		return 0;

	uint64_t **host_addr = malloc(nb_bufs * sizeof(uint64_t *));
	
	ret = rte_ring_dequeue_burst(ring, (void **)host_addr, nb_bufs, NULL);
	for(int i = 0; i < ret; i++) {
		bufs[i] = (struct rte_mbuf *)(*(host_addr[i]));
		// if(internal->rx_csum)
		// 	zcio_dev_rx_sw_csum(bufs[i]);
		free(host_addr[i]);
		rx_queue->packet_bytes += bufs[i]->pkt_len;
		rx_queue->packet_num++;
	}
	free(host_addr);
	return ret;

}

static uint16_t
eth_zcio_server_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *vq = q;
	struct pmd_internal *internal = container_of(vq, struct pmd_internal, tx_queue);
	if(rte_atomic16_read(&internal->attched) == 0)
		return 0;
	struct zcio_msg msg = {
		.type = ZCIO_MSG_DATA_PKT,
	};
	
	uint16_t avail_bufs = nb_bufs;
	uint16_t sent_bufs = 0;
	uint64_t total_bytes = 0;
	while(avail_bufs > 0) {
		if(avail_bufs <= ZCIO_MAX_BURST) {
			msg.payload.packets.pkt_num = avail_bufs;
			for(int i = 0; i < avail_bufs; i++) {
				msg.payload.packets.host_start_addr[i] = (uint64_t)bufs[sent_bufs + i];
				total_bytes += bufs[sent_bufs + i]->pkt_len;
				// if(internal->tx_csum)
				// 	zcio_dev_tx_sw_csum(bufs[sent_bufs + i]);
			}
			zcio_send_msg(vq->sock, &msg);
			sent_bufs += avail_bufs;
			avail_bufs = 0;
			break;
		}
		
		msg.payload.packets.pkt_num = ZCIO_MAX_BURST;
		for(int i = 0; i < ZCIO_MAX_BURST; i++) {
			msg.payload.packets.host_start_addr[i] = (uint64_t)bufs[sent_bufs + i];
			total_bytes += bufs[sent_bufs + i]->pkt_len;
			// if(internal->tx_csum)
			// 	zcio_dev_tx_sw_csum(bufs[sent_bufs + i]);
		}
		zcio_send_msg(vq->sock, &msg);
		sent_bufs += ZCIO_MAX_BURST;
		avail_bufs -= ZCIO_MAX_BURST;
	}
	
	vq->packet_num += sent_bufs;
	vq->packet_bytes += total_bytes;
	
	return sent_bufs;
}

static int
addr2idx(void *addr, struct meminfo *meminfo)
{
	uint64_t addr_val = (uint64_t)addr;
	uint64_t start_addr = 0;
	uint64_t end_addr = 0;
	for (int i = 0; i < meminfo->region_nr; i++) {
		if(is_bit_set(meminfo->invalid_mask, i))
			continue;
		start_addr = meminfo->regions[i].satrt_addr + meminfo->regions[i].mmap_offset;
		end_addr = start_addr + meminfo->regions[i].memory_size;
		if (addr_val >= start_addr && addr_val < end_addr)
			return i;
 	}
	return -1;
}

static uint64_t 
addr_translation(uint64_t addr, struct memory_region *src, 
	struct memory_region *dst)
{
	uint64_t ret = 0;
	ret = addr - src->satrt_addr - src->mmap_offset;
	ret = ret + dst->satrt_addr + dst->mmap_offset;
	return ret;
}

static struct rte_mbuf *
mbuf_addr_translation_client_rx(uint64_t addr, struct memory_region *src, 
	struct memory_region *dst)
{
	uint64_t buf_addr;
	uint64_t next_addr;
	struct rte_mbuf *head = (struct rte_mbuf *)addr_translation(addr, src, dst);
	struct rte_mbuf *tmp_buf;
	
	if(head->nb_segs < 1)
		return NULL;
	
	tmp_buf = head;
	for(int i = 0; i < head->nb_segs; i++) {
		buf_addr = addr_translation((uint64_t)tmp_buf->buf_addr, src, dst);
		tmp_buf->buf_addr = (void *)buf_addr;
		next_addr = addr_translation((uint64_t)tmp_buf->next, src, dst);
		tmp_buf->next = (struct rte_mbuf *)next_addr;
		tmp_buf = tmp_buf->next;
	}
	
	return head;
}

static uint64_t
mbuf_addr_translation_client_tx(struct rte_mbuf* m, struct memory_region *src, 
	struct memory_region *dst)
{
	if(m->nb_segs < 1)
		return 0;
	
	uint64_t host_addr = addr_translation((uint64_t)m, src, dst);
	
	uint64_t buf_addr = 0;
	uint64_t next_addr;
	struct rte_mbuf *tmp_mbuf = m;
	struct rte_mbuf *next_mbuf;
	
	for(int i = 0; i < m->nb_segs; i++) {
		next_mbuf = tmp_mbuf->next;
		buf_addr = (uint64_t)(tmp_mbuf->buf_addr);
		buf_addr = addr_translation(buf_addr, src, dst);
		tmp_mbuf->buf_addr = (void *)buf_addr;
		next_addr = (uint64_t)tmp_mbuf->next;
		next_addr = addr_translation(next_addr, src, dst);
		tmp_mbuf->next = (struct rte_mbuf *)next_addr;
		tmp_mbuf = next_mbuf;
	}
	
	return host_addr;
}

/**
 * nb_bufs最大值设置为32767， 最高位设置为flag
 * flag = 0 时， nb_bufs为待收取的携带实际数据的包个数
 * flag = 1 时， nb_bufs为待收取的空闲数据包的包个数
 */
static uint16_t
eth_zcio_client_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *vq = q;
	struct pmd_internal *internal = container_of(vq, struct pmd_internal, rx_queue);
	struct rte_ring *data_ring = vq->data_pkt_ring;
	struct rte_ring *free_ring = vq->free_pkt_ring;
	struct rte_mbuf *tmp_mbuf;
	uint64_t tmp_addr;
	uint64_t tmp_bytes = 0;
	uint64_t tmp_pkts = 0;
	int i = 0, ret = 0, idx = -1;
	int recv_num = 0;
	uint64_t **host_addr = NULL;

	if(bufs == NULL) {
		ZCIO_LOG(ERR, "RX bufs is NULL");
		return 0;
	}
	
	if(rte_atomic16_read(&internal->attched) == 0)
		return 0;
	
	// 接收空闲数据包，在client端分配数据包
	if(nb_bufs > MAX_RX_BURST_NUM) {
		struct zcio_msg msg = {
			.type = ZCIO_MSG_REQUEST_PKT,
		};
		unsigned int request_num = 0;
		unsigned int free_avail_num = 0;
		unsigned int free_num = nb_bufs - MAX_RX_BURST_NUM;
		if(free_num > MAX_FREE_QUEUE_SIZE) {
			ZCIO_LOG(ERR, "Error: request too many free pkt\n");
			return 0;
		}
		host_addr = malloc(free_num * sizeof(uint64_t *));
		ret = rte_ring_dequeue_bulk(free_ring, (void **)host_addr, free_num, &free_avail_num);
		if(ret == 0) {
			request_num = (free_num - free_avail_num) < 16 ? 16 : (free_num - free_avail_num);
			request_num = request_num > (MAX_FREE_QUEUE_SIZE - free_avail_num) ? 
						(MAX_FREE_QUEUE_SIZE - free_avail_num) : 
						request_num;
			msg.payload.pkt_num = request_num;
			zcio_send_msg(vq->sock, &msg);
			while(ret == 0) {
				ret = rte_ring_dequeue_bulk(free_ring, (void **)host_addr, free_num, &free_avail_num);
			}
		}
		for(i = 0; i < ret; i++) {
			tmp_addr = *(host_addr[i]);
			free(host_addr[i]);
			idx = addr2idx((void *)tmp_addr, &internal->host_mem);
			if(idx == -1) {
				ZCIO_LOG(ERR, "addr2idx: rx invalid packet address %lx\n", (uint64_t)bufs[i]);
				continue;
			}
			tmp_mbuf = mbuf_addr_translation_client_rx(tmp_addr, &internal->host_mem.regions[idx], 
				&internal->guest_mem.regions[idx]);
			if(tmp_mbuf == NULL) {
				ZCIO_LOG(ERR, "addr_translation: rx invalid packet address %lx\n", (uint64_t)bufs[i]);
				continue;
			}
			
			tmp_mbuf->dynfield1[0] = 0; // 清除FREE标志位
			bufs[recv_num] = tmp_mbuf;
			tmp_bytes += bufs[recv_num]->pkt_len;
			tmp_pkts++;
			recv_num++;
		}
		free(host_addr);
		vq->packet_bytes += tmp_bytes;
		vq->packet_num += tmp_pkts;
		return recv_num;
	}
	
	host_addr = malloc(nb_bufs * sizeof(uint64_t *));
	ret = rte_ring_dequeue_burst(data_ring, (void **)host_addr, nb_bufs, NULL);
	for(i = 0; i < ret; i++) {
		tmp_addr = *(host_addr[i]);
		free(host_addr[i]);
		idx = addr2idx((void *)tmp_addr, &internal->host_mem);
		if(idx == -1) {
			ZCIO_LOG(ERR, "addr2idx: rx invalid packet address %lx\n", (uint64_t)bufs[i]);
			continue;
		}

		tmp_mbuf = mbuf_addr_translation_client_rx(tmp_addr, &internal->host_mem.regions[idx], 
			&internal->guest_mem.regions[idx]);
		if(tmp_mbuf == NULL) {
			ZCIO_LOG(ERR, "addr_translation: rx invalid packet address %lx\n", (uint64_t)bufs[i]);
			continue;
		}
		bufs[recv_num] = tmp_mbuf;
		// if(internal->rx_csum)
		// 	zcio_dev_rx_sw_csum(bufs[recv_num]);
		tmp_bytes += bufs[recv_num]->pkt_len;
		tmp_pkts++;
		recv_num++;
	}
	free(host_addr);
	vq->packet_bytes += tmp_bytes;
	vq->packet_num += tmp_pkts;
	return recv_num;
}

/**
 * 当发送数据包的dynfield1[0]为114514，则表示该数据包为待释放包
 */
static uint16_t
eth_zcio_client_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *vq = q;
	struct pmd_internal *internal = container_of(vq, struct pmd_internal, tx_queue);
	struct zcio_msg msg = {
		.type = ZCIO_MSG_DATA_PKT,
	};
	int idx = 0;
	uint64_t host_addr = 0;
	uint16_t avail_bufs = nb_bufs;
	uint16_t sent_bufs = 0;
	uint64_t total_bytes = 0;
	uint64_t epoch_bytes = 0;
	
	if(rte_atomic16_read(&internal->attched) == 0)
		return 0;
		
	if(bufs == NULL)
		return 0;
	
	if(bufs[0]->dynfield1[0] == 114514) {
		msg.type = ZCIO_MSG_FREE_PKT;
	}
	
	while(avail_bufs > 0) {
		epoch_bytes = 0;
		if(avail_bufs <= ZCIO_MAX_BURST) {
			msg.payload.packets.pkt_num = avail_bufs;
			for(int i = 0; i < avail_bufs; i++) {
				idx = addr2idx((void*)bufs[sent_bufs + i], &internal->guest_mem);
				if(idx == -1) {
					ZCIO_LOG(ERR, "addr2idx: tx invalid packet address %lx\n", (uint64_t)bufs[sent_bufs + i]);
					goto out;
				}
				epoch_bytes += bufs[sent_bufs + i]->pkt_len;
				// if(internal->tx_csum)
				// 	zcio_dev_tx_sw_csum(bufs[sent_bufs + i]);
				host_addr = mbuf_addr_translation_client_tx(bufs[sent_bufs + i], 
					&internal->guest_mem.regions[idx], &internal->host_mem.regions[idx]);
				msg.payload.packets.host_start_addr[i] = host_addr;
				bufs[sent_bufs + i] = NULL;
			}
			zcio_send_msg(vq->sock, &msg);
			sent_bufs += avail_bufs;
			avail_bufs = 0;
			total_bytes += epoch_bytes;
			break;
		}
		
		msg.payload.packets.pkt_num = ZCIO_MAX_BURST;
		for(int i = 0; i < ZCIO_MAX_BURST; i++) {
			idx = addr2idx((void*)bufs[sent_bufs + i], &internal->guest_mem);
			if(idx == -1) {
				ZCIO_LOG(ERR, "addr2idx: tx invalid packet address %lx\n", (uint64_t)bufs[sent_bufs + i]);
				goto out;
			}
			epoch_bytes += bufs[sent_bufs + i]->pkt_len;
			// if(internal->tx_csum)
			// 	zcio_dev_tx_sw_csum(bufs[sent_bufs + i]);
			host_addr = mbuf_addr_translation_client_tx(bufs[sent_bufs + i], 
				&internal->guest_mem.regions[idx], &internal->host_mem.regions[idx]);
			msg.payload.packets.host_start_addr[i] = host_addr;
			bufs[sent_bufs + i] = NULL;
		}
		zcio_send_msg(vq->sock, &msg);
		sent_bufs += ZCIO_MAX_BURST;
		avail_bufs -= ZCIO_MAX_BURST;
		total_bytes += epoch_bytes;
	}

 out:
	
	vq->packet_num += sent_bufs;
	vq->packet_bytes += total_bytes;
	
	return sent_bufs;
}

// todo Get the number of used Rx descriptors
static uint32_t 
eth_zcio_rx_queue_count(void *rxq)
{
	return 0;
}

static int
eth_dev_zcio_create(struct rte_vdev_device *dev, int server, int queues,
        char *info_name, const unsigned int numa_node)
{
	const char *name = rte_vdev_device_name(dev);
	struct rte_eth_dev_data *data;
	struct pmd_internal *internal = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct rte_ether_addr *eth_addr = NULL;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_vdev_allocate(dev, sizeof(*internal));
	if (eth_dev == NULL)
		goto error;
	data = eth_dev->data;

	eth_addr = rte_zmalloc_socket(name, sizeof(*eth_addr), 0, numa_node);
	if (eth_addr == NULL)
		goto error;
	data->mac_addrs = eth_addr;
	*eth_addr = base_eth_addr;
	eth_addr->addr_bytes[5] = eth_dev->data->port_id;
	
	/* pmd_internal 初始化 */

	// info_name 初始化
	internal = eth_dev->data->dev_private;
	internal->info_name = rte_malloc_socket(name, strlen(info_name) + 1, 0, numa_node);
	if (!internal->info_name)
		goto error;
	strcpy(internal->info_name, info_name);

	// server 标志位
	internal->server = server == 1 ? true : false;
	if(internal->server && rte_eal_process_type() != RTE_PROC_PRIMARY) {
		ZCIO_LOG(ERR, "server mode only support primary process\n");
		goto error;
	}
	if(!internal->server && rte_eal_process_type() != RTE_PROC_SECONDARY) {
		ZCIO_LOG(ERR, "client mode only support secondary process\n");
		goto error;
	}
	
	// rte_eth_dev_data 初始化
	queues = RTE_MIN(queues, MAX_QUEUES_NUM);
	data->nb_rx_queues = queues;
	data->nb_tx_queues = queues;
	internal->max_queues = queues;
	data->dev_link = pmd_link;
	data->promiscuous = 1;
	data->all_multicast = 1;

	eth_dev->dev_ops = &eth_zcio_ops;
	eth_dev->rx_queue_count = eth_zcio_rx_queue_count;

	/* finally assign rx and tx ops */
	if(internal->server) {
		eth_dev->rx_pkt_burst = eth_zcio_server_rx;
		eth_dev->tx_pkt_burst = eth_zcio_server_tx;
	}else {
		eth_dev->rx_pkt_burst = eth_zcio_client_rx;
		eth_dev->tx_pkt_burst = eth_zcio_client_tx;
	}
	
	rte_eth_dev_probing_finish(eth_dev);
	return 0;

 error:
	rte_eth_dev_release_port(eth_dev);

	return -1;
}

static int
rte_pmd_zcio_probe(struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist = NULL;
    char *info_name = NULL;
    int server = 1;
    int queues = 1;
	int ret = 0;

	const char *name = rte_vdev_device_name(dev);
	ZCIO_LOG(INFO, "Initializing PMD_ZCIO for %s\n", name);

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
	if (kvlist == NULL) {
		ZCIO_LOG(ERR, "Invalid parameters for %s\n", name);
		return -1;
	}
		
    // 解析 server 参数
    ret = parse_kvargs(kvlist, ETH_ZCIO_SERVER_ARG, &open_int, &server);
    if(ret < 0) {
        ZCIO_LOG(ERR, "server-mode param error\n");
		goto out_free; 
    }

    // 解析 info-name 参数
    ret = parse_kvargs(kvlist, ETH_ZCIO_INFO_NAME_ARG, &open_str, &info_name);
    if(ret < 0) {
        ZCIO_LOG(ERR, "info-name param error\n");
		goto out_free;
    }
    
    // 解析 queues 参数
	if(rte_kvargs_count(kvlist, ETH_ZCIO_QUEUES_ARG) == 1) {
		ret = parse_kvargs(kvlist, ETH_ZCIO_QUEUES_ARG, &open_int, &queues);
		if(ret < 0) {
			ZCIO_LOG(ERR, "queues param error\n");
			queues = 1; 
    	}
	}
    
	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

	ret = eth_dev_zcio_create(dev, server, queues, info_name,
                dev->device.numa_node);
	if (ret < 0)
		ZCIO_LOG(ERR, "Failed to create %s\n", name);

 out_free:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
rte_pmd_zcio_remove(struct rte_vdev_device *dev)
{
	const char *name;
	struct rte_eth_dev *eth_dev = NULL;

	name = rte_vdev_device_name(dev);
	ZCIO_LOG(INFO, "Un-Initializing pmd_zcio for %s\n", name);

	/* find an ethdev entry */
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return 0;

	eth_dev_close(eth_dev);
	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_vdev_driver pmd_zcio_drv = {
	.probe = rte_pmd_zcio_probe,
	.remove = rte_pmd_zcio_remove,
};

RTE_PMD_REGISTER_VDEV(net_zcio, pmd_zcio_drv);
RTE_PMD_REGISTER_ALIAS(net_zcio, eth_zcio);
RTE_PMD_REGISTER_PARAM_STRING(net_zcio,
	"server=<0|1>"
    "info-name=<path>"
    "queues=<int>");