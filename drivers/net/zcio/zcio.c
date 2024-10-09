
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <rte_log.h>
#include <rte_bus_vdev.h>
#include <rte_kvargs.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <bus_vdev_driver.h>

#include "zcio.h"

RTE_LOG_REGISTER_DEFAULT(zcio_logtype, INFO);

#define ZCIO_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zcio_logtype, "ZCIO: "fmt, ##args)

#define ETH_ZCIO_SERVER_ARG		        "server"
#define ETH_ZCIO_SERVER_IFACE_ARG       "server-iface"
#define ETH_ZCIO_QUEUES_ARG		        "queues"
#define ETH_ZCIO_MEMCTL_IFACE_ARG		"memctl-iface"

static const char *valid_arguments[] = {
	ETH_ZCIO_SERVER_ARG,
    ETH_ZCIO_SERVER_IFACE_ARG,
    ETH_ZCIO_QUEUES_ARG,
	ETH_ZCIO_MEMCTL_IFACE_ARG,
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

static int
eth_dev_start(struct rte_eth_dev *eth_dev)
{
	struct pmd_internal *internal = eth_dev->data->dev_private;
	// struct rte_eth_conf *dev_conf = &eth_dev->data->dev_conf;
	uint16_t i;

	rte_atomic16_set(&internal->started, 1);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		eth_dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static int
eth_dev_stop(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	uint16_t i;

	dev->data->dev_started = 0;
	rte_atomic16_set(&internal->started, 0);

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

static int
eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal;
	int ret;

	internal = dev->data->dev_private;
	if (!internal)
		return 0;
	
	// fd_set_try_del(internal->fd_set, internal->memctl_fd);
	if(internal->server) {
		ret = fd_set_try_del(&internal->fd_set, 
			internal->unix_sock[TYPE_SERVER_2_CLIENT].sock_fd);
		while(ret == -1) {
			usleep(100);
			ret = fd_set_try_del(&internal->fd_set, 
				internal->unix_sock[TYPE_SERVER_2_CLIENT].sock_fd);
		}
		if(internal->unix_sock[TYPE_SERVER_2_CLIENT].sock_fd != -1)
			close(internal->unix_sock[TYPE_SERVER_2_CLIENT].sock_fd);
	}else {
		ret = fd_set_try_del(&internal->fd_set, 
			internal->unix_sock[TYPE_CLIENT_2_SERVER].sock_fd);
		while(ret == -1) {
			usleep(100);
			ret = fd_set_try_del(&internal->fd_set, 
				internal->unix_sock[TYPE_CLIENT_2_SERVER].sock_fd);
		}
		if(internal->unix_sock[TYPE_CLIENT_2_SERVER].sock_fd != -1)
			close(internal->unix_sock[TYPE_CLIENT_2_SERVER].sock_fd);

		if(internal->guest_mem.region_nr != 0) {
			for(int i = 0; i < internal->guest_mem.region_nr; i++) {
				if(is_bit_set(internal->guest_mem.invalid_mask, i))
					continue;
				else {
					munmap((void*)internal->guest_mem.regions[i].satrt_addr, 
						internal->guest_mem.regions[i].memory_size);
					close(internal->guest_mem.fds[i]);
				}
			}
		}
	}

	ret = eth_dev_stop(dev);
	
	if(internal->server) {
		unlink(internal->server_iface);
	}
	rte_ring_free(internal->rx_queue.ring);
	rte_free(internal->server_iface);
	rte_free(internal->memctl_iface);
	rte_free(internal);

	dev->data->dev_private = NULL;

	return ret;
}

static void
zcio_server_msg_handler(int client_fd, void *dat, int *remove) 
{
	struct rte_eth_dev *dev = dat;
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *rx_queue = &internal->rx_queue;
	struct rte_ring *rx_ring = rx_queue->ring;
	struct msghdr msgh;
    struct iovec iov;
	struct zcio_msg msg;
	int ret = 0;
	
	// 初始化msghdr结构
    memset(&msgh, 0, sizeof(msgh));
	memset(&msg, 0, sizeof(msg));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

	// 初始化iov结构
    iov.iov_base = &msg;
    iov.iov_len = sizeof(msg);

	ret = recvmsg(client_fd, &msgh, 0);
	if (ret < 0) {
		ZCIO_LOG(ERR, "SERVER_2_CLIENT recvmsg failed\n");
		return;
	}else if(ret == 0) {
		ZCIO_LOG(INFO, "client close the connection\n");
		close(client_fd);
		internal->unix_sock[TYPE_SERVER_2_CLIENT].sock_fd = -1;
		*remove = 1;
		return;
	}
	
	uint16_t pkt_num = msg.payload.packets.pkt_num;
	uint64_t **host_addr = malloc(pkt_num * sizeof(uint64_t *));
	for(int i = 0; i < pkt_num; i++) {
		host_addr[i] = malloc(sizeof(uint64_t));
		*(host_addr[i]) = msg.payload.packets.host_start_addr[i];
	}
		
	switch(msg.type) {
		case ZCIO_MSG_PACKET: {
			if(!rte_ring_enqueue_bulk(rx_ring, (void **)host_addr, pkt_num, NULL)) {
				ZCIO_LOG(ERR, "server rx_ring is full\n");
				for(int i = 0; i < pkt_num; i++)
					free(host_addr[i]);
			}
			free(host_addr);
		} break;
		default:
			ZCIO_LOG(ERR, "unknown msg type\n");
			for(int i = 0; i < pkt_num; i++)
				free(host_addr[i]);
			free(host_addr);
			break;
	}
	
	return;
}

static void
zcio_client_msg_handler(int server_fd, void *dat, int *remove __rte_unused) 
{
	struct rte_eth_dev *dev = dat;
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *rx_queue = &internal->rx_queue;
	struct rte_ring *rx_ring = rx_queue->ring;
	struct msghdr msgh;
    struct iovec iov;
	struct zcio_msg msg;
	int ret = 0;
	
	// 初始化msghdr结构
    memset(&msgh, 0, sizeof(msgh));
	memset(&msg, 0, sizeof(msg));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

	// 初始化iov结构
    iov.iov_base = &msg;
    iov.iov_len = sizeof(msg);

	ret = recvmsg(server_fd, &msgh, 0);
	if (ret < 0) {
		ZCIO_LOG(ERR, "SERVER_2_CLIENT recvmsg failed\n");
		return;
	}else if(ret == 0) {
		ZCIO_LOG(INFO, "server close the connection\n");
		close(server_fd);
		internal->unix_sock[TYPE_CLIENT_2_SERVER].sock_fd = -1;
		*remove = 1;
		return;
	}
	
	uint16_t pkt_num = msg.payload.packets.pkt_num;
	uint64_t **host_addr = malloc(pkt_num * sizeof(uint64_t *));
	for(int i = 0; i < pkt_num; i++) {
		host_addr[i] = malloc(sizeof(uint64_t));
		*(host_addr[i]) = msg.payload.packets.host_start_addr[i];
	}
		
	switch(msg.type) {
		case ZCIO_MSG_PACKET: {
			if(!rte_ring_enqueue_bulk(rx_ring, (void **)host_addr, pkt_num, NULL)) {
				ZCIO_LOG(ERR, "client rx_ring is full\n");
				for(int i = 0; i < pkt_num; i++)
					free(host_addr[i]);
			}
			free(host_addr);
		} break;
		default:
			ZCIO_LOG(ERR, "unknown msg type\n");
			for(int i = 0; i < pkt_num; i++)
				free(host_addr[i]);
			free(host_addr);
			break;
	}
	
	return;
}

static int
zcio_start_server(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_socket *sock = NULL;
	struct sockaddr_un *un = NULL;
	int fd = 0;
	int ret = 0;
	
	ZCIO_LOG(INFO, "ZCIO server configure\n");
	sock = &(internal->unix_sock[TYPE_SERVER_LISTENER]);
	
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto out;
	
	// ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	// if(ret < 0) {
	// 	ZCIO_LOG(ERR, "failed to set fd to non-blocking mode\n");
	// 	goto out_free_fd;
	// }
	
	un = &sock->un;
	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, internal->server_iface, sizeof(un->sun_path));
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';
	
	sock->sock_fd = fd;

	ret = bind(fd, (struct sockaddr *)&sock->un, sizeof(sock->un));
	if (ret < 0) {
		ZCIO_LOG(ERR, "failed to bind: %s; remove it and try again\n",
			strerror(errno));
		goto out_free_fd;
	}

	ret = listen(fd, 4);
	if (ret < 0)
		goto out_free_fd;
	
	ZCIO_LOG(INFO, "listening on %s\n", internal->server_iface);
	
	struct zcio_socket *client_sock = &(internal->unix_sock[TYPE_SERVER_2_CLIENT]);
	int client_fd;
	client_fd = accept(fd, NULL, NULL);
	if (client_fd < 0) {
		ZCIO_LOG(ERR, "failed to accept client connection: %s\n",
			strerror(errno));
		goto out_free_fd;
	}
		
	ZCIO_LOG(INFO, "[%s] new zcio connection fd is %d\n",internal->server_iface, client_fd);
	ret = fd_set_add(&internal->fd_set, client_fd, zcio_server_msg_handler,
			NULL, dev);
	if (ret < 0) {
		ZCIO_LOG(ERR, "[%s] failed to add fd %d into zcio server fd_set\n", 
					internal->server_iface, client_fd);
		close(client_fd);
		goto out_free_fd;
	}
	
	client_sock->sock_fd = client_fd;
	rte_atomic16_set(&internal->attched, 1);
	fd_set_pipe_notify(&internal->fd_set);
	
	close(fd);
	ZCIO_LOG(INFO, "ZCIO server accept client succeeded\n");
	return 0;

 out_free_fd:
	close(fd);

 out:
	return -1;
}

static void dump_meminfo(struct meminfo *meminfo)
{
	printf(" mem_region num %d\n", meminfo->region_nr);
	for (int i = 0; i < meminfo->region_nr; i++) {
		if(is_bit_set(meminfo->invalid_mask, i))
			continue;
		printf("	region %d: fd %d, start_addr: %lx, size: %lu\n", 
			   i, meminfo->fds[i], meminfo->regions[i].satrt_addr, 
			   meminfo->regions[i].memory_size);
	}
}

static int client_connect_server(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_socket *sock = NULL;
	struct sockaddr_un *un = NULL;
	int server_fd = 0;
	int ret = 0;
	int reconnect_count = 0;

	ZCIO_LOG(INFO, "ZCIO client connecting server\n");

	// 连接 server 模块
	sock = &(internal->unix_sock[TYPE_CLIENT_2_SERVER]);

	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        ZCIO_LOG(ERR, "CLIENT_2_SERVER socket creation failed\n");
        return -1;
    }

	un = &sock->un;
	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, internal->server_iface, sizeof(un->sun_path) - 1);
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';

	ret = connect(server_fd, (struct sockaddr *)un, sizeof(*un));
	while(ret < 0 && reconnect_count < MAX_RECONNECT) {
		ZCIO_LOG(ERR, "CLIENT_2_SERVER connect failed\n");
		sleep(2);
		ret = connect(server_fd, (struct sockaddr *)un, sizeof(*un));
		reconnect_count++;
	}
	if(ret < 0)
		return ret;
	
	sock->sock_fd = server_fd;
	ret = fd_set_add(&internal->fd_set, server_fd, zcio_client_msg_handler,
		  NULL, dev);
	if (ret < 0) {
		ZCIO_LOG(ERR, "client2server_fd %d faild to be added into fd_set\n",
			server_fd);
		close(server_fd);
		return -1;
	}
	ZCIO_LOG(INFO, "CLIENT_2_SERVER connect succeeded\n");
	rte_atomic16_set(&internal->attched, 1);
	return 0;
}

static int
zcio_start_client(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_socket *sock = NULL;
	struct sockaddr_un *un = NULL;
	struct msghdr msgh;
    struct iovec iov;
    struct cmsghdr *cmsg;
    char control[CMSG_SPACE(MAX_FD_NUM * sizeof(int))];
	struct stat fd_state;
	int fd_num = 0;
	int memctl_fd = 0;
	int ret = 0;
	
	ZCIO_LOG(INFO, "ZCIO client mode configure\n");
	
	// 连接 memctl 模块
	sock = &(internal->unix_sock[TYPE_CLIENT_2_MEMCTL]);
	memctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (memctl_fd == -1) {
        ZCIO_LOG(ERR, "CLIENT_2_MEMCTL socket creation failed\n");
        goto out;
    }

	un = &sock->un;
	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, internal->memctl_iface, sizeof(un->sun_path) - 1);
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';

	ret = connect(memctl_fd, (struct sockaddr *)un, sizeof(*un));
	if(ret < 0) {
		ZCIO_LOG(ERR, "CLIENT_2_MEMCTL connect failed\n");
		goto out_free_fd;
	}

	// 初始化msghdr结构
    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);

	// 初始化iov结构
    iov.iov_base = &internal->host_mem;
    iov.iov_len = sizeof(internal->host_mem);

	ret = recvmsg(memctl_fd, &msgh, MSG_CMSG_CLOEXEC);
	if (ret < 0) {
		ZCIO_LOG(ERR, "CLIENT_2_MEMCTL recvmsg failed\n");
		goto out_free_fd;
	}

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
		cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if ((cmsg->cmsg_level == SOL_SOCKET) &&
			(cmsg->cmsg_type == SCM_RIGHTS)) {
			fd_num = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			internal->guest_mem.region_nr = fd_num;
			memcpy(internal->guest_mem.fds, CMSG_DATA(cmsg), fd_num * sizeof(int));
			break;
		}
	}
	
	// 获取内存信息
	int *fds = internal->guest_mem.fds;
	struct memory_region *regions = internal->guest_mem.regions;
	uint64_t *invalid_mask = &internal->guest_mem.invalid_mask;
	for (int i = 0; i < fd_num; i++) {
		ret = fstat(fds[i], &fd_state);
		if(ret) {
			ZCIO_LOG(ERR, "failed to fstat fd %d\n", fds[i]);
			close(fds[i]);
			set_bit(invalid_mask, i);
			continue;
		}
		regions[i].satrt_addr = (uint64_t)mmap(NULL, fd_state.st_size, 
					(PROT_READ|PROT_WRITE), MAP_SHARED, fds[i], 0);
		if (regions[i].satrt_addr == (uint64_t)MAP_FAILED) {
			ZCIO_LOG(ERR, "failed to mmap fd %d: %s\n", fds[i], strerror(errno));
			close(fds[i]);
			set_bit(invalid_mask, i);
			continue;
		}
		regions[i].memory_size = fd_state.st_size;
		regions[i].mmap_offset = internal->host_mem.regions[i].mmap_offset;
 	}
	
	ZCIO_LOG(INFO, "Host meminfo:");
	dump_meminfo(&internal->host_mem);
	ZCIO_LOG(INFO, "Guest meminfo:");
	dump_meminfo(&internal->guest_mem);
	close(memctl_fd);
	
	// 连接 server
	ret = client_connect_server(dev);
	if(ret < 0) {
		ZCIO_LOG(ERR, "failed to connect to server\n");
		for(int i = 0; i < fd_num; i++)
			close(fds[i]);
		goto out;
	}
	
	return 0;

 out_free_fd:
	close(memctl_fd);

 out:
	return -1;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	
	// 创建轮询线程，处理文件描述符集合的读写回调函数
	static rte_thread_t fd_set_tid;
	if (fd_set_tid.opaque_id == 0) {
		if (fd_set_pipe_init(&internal->fd_set) < 0) {
			ZCIO_LOG(ERR, "failed to create pipe for zcio fd_set\n");
			return -1;
		}

		int ret = rte_thread_create_internal_control(&fd_set_tid,
				"zcio-evt", fd_set_event_dispatch, &internal->fd_set);
		if (ret != 0) {
			ZCIO_LOG(ERR, "failed to create fd_set handling thread\n");
			fd_set_pipe_uninit(&internal->fd_set);
			return -1;
		}
	}

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

	return 0;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		   uint16_t nb_rx_desc, unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool __rte_unused)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *vq = &internal->rx_queue;

	vq->ring = rte_ring_create("zcio_rx_queue", nb_rx_desc, socket_id,
				  RING_F_SP_ENQ |RING_F_SC_DEQ);
	if(internal->server)
		vq->sock = &(internal->unix_sock[TYPE_SERVER_2_CLIENT]);
	else
		vq->sock = &(internal->unix_sock[TYPE_CLIENT_2_SERVER]);
	dev->data->rx_queues[rx_queue_id] = vq;

	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		   uint16_t nb_tx_desc __rte_unused, 
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *vq = &internal->tx_queue;
	if(internal->server)
		vq->sock = &(internal->unix_sock[TYPE_SERVER_2_CLIENT]);
	else
		vq->sock = &(internal->unix_sock[TYPE_CLIENT_2_SERVER]);
	dev->data->tx_queues[tx_queue_id] = vq;

	return 0;
}

static void
eth_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid __rte_unused)
{
	struct pmd_internal *internal = dev->data->dev_private;
	rte_ring_free(internal->rx_queue.ring);
	return;
}

static void
eth_tx_queue_release(struct rte_eth_dev *dev __rte_unused, uint16_t qid __rte_unused)
{
	// nothing to do
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
	
	stats->ipackets = rxq->packet_num;
	stats->opackets = txq->packet_num;
	stats->ibytes = rxq->packet_bytes;
	stats->obytes = txq->packet_bytes;

	return 0;
}

static int
eth_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_queue *rxq = &internal->rx_queue;
	struct zcio_queue *txq = &internal->tx_queue;

	rxq->packet_bytes = 0;
	rxq->packet_num = 0;
	txq->packet_bytes = 0;
	txq->packet_num = 0;

	return 0;
}

static int
zcio_dev_priv_dump(struct rte_eth_dev *dev __rte_unused, FILE *f)
{
	// struct pmd_internal *internal = dev->data->dev_private;
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

static int
zcio_send_msg(int sock, struct zcio_msg *msg)
{
	int r;
	struct msghdr msgh;
	struct iovec iov;

	memset(&msgh, 0, sizeof(msgh));

	iov.iov_base = (void *)msg;
	iov.iov_len = sizeof(struct zcio_msg);

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	do {
		r = sendmsg(sock, &msgh, 0);
	} while (r < 0 && errno == EINTR);

	if (r < 0)
		ZCIO_LOG(ERR, "Failed to send msg: %s", strerror(errno));

	return r;
}

static uint16_t
eth_zcio_server_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *rx_queue = q;
	struct rte_ring *ring = rx_queue->ring;
	uint64_t **host_addr = malloc(nb_bufs * sizeof(uint64_t *));
	int ret = 0;

	ret = rte_ring_dequeue_burst(ring, (void **)host_addr, nb_bufs, NULL);
	for(int i = 0; i < ret; i++) {
		bufs[i] = (struct rte_mbuf *)(*(host_addr[i]));
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
		.type = ZCIO_MSG_PACKET,
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
			}
			zcio_send_msg(vq->sock->sock_fd, &msg);
			sent_bufs += avail_bufs;
			avail_bufs = 0;
			break;
		}
		
		msg.payload.packets.pkt_num = ZCIO_MAX_BURST;
		for(int i = 0; i < ZCIO_MAX_BURST; i++) {
			msg.payload.packets.host_start_addr[i] = (uint64_t)bufs[sent_bufs + i];
			total_bytes += bufs[sent_bufs + i]->pkt_len;
		}
		zcio_send_msg(vq->sock->sock_fd, &msg);
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

static uint16_t
eth_zcio_client_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *vq = q;
	struct pmd_internal *internal = container_of(vq, struct pmd_internal, rx_queue);
	struct rte_ring *ring = vq->ring;
	uint64_t **host_addr = malloc(nb_bufs * sizeof(uint64_t *));
	uint64_t tmp_addr;
	uint64_t tmp_bytes = 0;
	uint64_t tmp_pkts = 0;
	int i = 0, ret = 0;
	int idx = -1;
	int recv_num = 0;

	ret = rte_ring_dequeue_burst(ring, (void **)host_addr, nb_bufs, NULL);
	for(i = 0; i < ret; i++) {
		tmp_addr = *(host_addr[i]);
		free(host_addr[i]);
		idx = addr2idx((void *)tmp_addr, &internal->host_mem);
		if(idx == -1) {
			ZCIO_LOG(ERR, "invalid packet address %lx", (uint64_t)bufs[i]);
			continue;
		}
		// rte_mbuf转换
		tmp_addr = tmp_addr - internal->host_mem.regions[idx].satrt_addr 
			- internal->host_mem.regions[idx].mmap_offset;
		tmp_addr = tmp_addr + internal->guest_mem.regions[idx].satrt_addr 
			+ internal->guest_mem.regions[idx].mmap_offset;
		bufs[recv_num] = (struct rte_mbuf *)tmp_addr;
		
		// buf_addr转换
		tmp_addr = (uint64_t)bufs[recv_num]->buf_addr;
		tmp_addr = tmp_addr - internal->host_mem.regions[idx].satrt_addr 
			- internal->host_mem.regions[idx].mmap_offset;
		tmp_addr = tmp_addr + internal->guest_mem.regions[idx].satrt_addr 
			+ internal->guest_mem.regions[idx].mmap_offset;
		bufs[recv_num]->buf_addr = (void *)tmp_addr;
		tmp_bytes += bufs[i]->pkt_len;
		tmp_pkts++;
		recv_num++;
	}
	free(host_addr);
	vq->packet_bytes += tmp_bytes;
	vq->packet_num += tmp_pkts;
	return recv_num;
}

static uint16_t
eth_zcio_client_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct zcio_queue *vq = q;
	struct pmd_internal *internal = container_of(vq, struct pmd_internal, tx_queue);
	if(rte_atomic16_read(&internal->attched) == 0)
		return 0;
	struct zcio_msg msg = {
		.type = ZCIO_MSG_PACKET,
	};
	
	int idx = 0;
	uint64_t host_addr = 0;
	
	uint16_t avail_bufs = nb_bufs;
	uint16_t sent_bufs = 0;
	uint64_t total_bytes = 0;
	uint64_t epoch_bytes = 0;
	while(avail_bufs > 0) {
		epoch_bytes = 0;
		if(avail_bufs <= ZCIO_MAX_BURST) {
			msg.payload.packets.pkt_num = avail_bufs;
			for(int i = 0; i < avail_bufs; i++) {
				idx = addr2idx((void*)bufs[sent_bufs + i], &internal->guest_mem);
				if(idx == -1) {
					ZCIO_LOG(ERR, "invalid packet address %lx", (uint64_t)bufs[sent_bufs + i]);
					goto out;
				}
				// buf_addr转换
				host_addr = (uint64_t)bufs[sent_bufs + i]->buf_addr - internal->guest_mem.regions[idx].satrt_addr
					- internal->guest_mem.regions[idx].mmap_offset;
				host_addr = host_addr + internal->host_mem.regions[idx].satrt_addr 
					+ internal->host_mem.regions[idx].mmap_offset;
				bufs[sent_bufs + i]->buf_addr = (void *)host_addr;
				
				// rte_mbuf转换
				host_addr = (uint64_t)bufs[sent_bufs + i] - internal->guest_mem.regions[idx].satrt_addr
					- internal->guest_mem.regions[idx].mmap_offset;
				host_addr = host_addr + internal->host_mem.regions[idx].satrt_addr 
					+ internal->host_mem.regions[idx].mmap_offset;
				msg.payload.packets.host_start_addr[i] = host_addr;
				epoch_bytes += bufs[sent_bufs + i]->pkt_len;
			}
			zcio_send_msg(vq->sock->sock_fd, &msg);
			sent_bufs += avail_bufs;
			avail_bufs = 0;
			total_bytes += epoch_bytes;
			break;
		}
		
		msg.payload.packets.pkt_num = ZCIO_MAX_BURST;
		for(int i = 0; i < ZCIO_MAX_BURST; i++) {
			idx = addr2idx((void*)bufs[sent_bufs + i], &internal->guest_mem);
			if(idx == -1) {
				ZCIO_LOG(ERR, "invalid packet address %lx", (uint64_t)bufs[sent_bufs + i]);
				goto out;
			}
			host_addr = (uint64_t)bufs[sent_bufs + i] - internal->guest_mem.regions[idx].satrt_addr
				- internal->guest_mem.regions[idx].mmap_offset;
			host_addr = host_addr + internal->host_mem.regions[idx].satrt_addr 
				+ internal->host_mem.regions[idx].mmap_offset;
			msg.payload.packets.host_start_addr[i] = host_addr;
			epoch_bytes += bufs[sent_bufs + i]->pkt_len;
		}
		zcio_send_msg(vq->sock->sock_fd, &msg);
		sent_bufs += ZCIO_MAX_BURST;
		avail_bufs -= ZCIO_MAX_BURST;
		total_bytes += epoch_bytes;
	}

 out:
	
	vq->packet_num += sent_bufs;
	vq->packet_bytes += total_bytes;
	
	return sent_bufs;
}

static int
eth_dev_zcio_create(struct rte_vdev_device *dev, int server, int queues,
        char *memctl_iface, const unsigned int numa_node, char *server_iface)
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
	
	// pmd_internal 初始化
	internal = eth_dev->data->dev_private;
	internal->server_iface = rte_malloc_socket(name, strlen(server_iface) + 1, 0, numa_node);
	if (!internal->server_iface)
		goto error;
	strcpy(internal->server_iface, server_iface);

	internal->server = server == 1 ? true : false;
	if(!internal->server) {
		internal->memctl_iface = rte_malloc_socket(name, strlen(memctl_iface) + 1, 0, numa_node);
		if (!internal->memctl_iface)
			goto error;
		strcpy(internal->memctl_iface, memctl_iface);
	}else
		internal->memctl_iface = NULL;
	
	// rte_eth_dev_data 初始化
	data->nb_rx_queues = queues;
	data->nb_tx_queues = queues;
	data->dev_link = pmd_link;
	// data->dev_flags = RTE_ETH_DEV_INTR_LSC;
	data->promiscuous = 1;
	data->all_multicast = 1;

	eth_dev->dev_ops = &eth_zcio_ops;

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
	if (internal)
		rte_free(internal->memctl_iface);
	rte_eth_dev_release_port(eth_dev);

	return -1;
}

static inline int
open_iface(const char *key __rte_unused, const char *value, void *extra_args)
{
	const char **iface_name = extra_args;

	if (value == NULL)
		return -1;

	*iface_name = value;

	return 0;
}

static inline int
open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	uint16_t *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (uint16_t)strtoul(value, NULL, 0);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static inline int
parse_kvargs(struct rte_kvargs *kvlist, const char *key_match, 
        arg_handler_t handler, void *opaque)
{
    int ret = 0;
    ret = rte_kvargs_count(kvlist, key_match);
    if(ret != 1)
		return -1;
    
    ret = rte_kvargs_process(kvlist, key_match, handler, opaque);
    if(ret < 0) 
        return ret;
    
    return 0;
}

static int
rte_pmd_zcio_probe(struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist = NULL;
    char *server_iface = NULL;
    char *memctl_iface = NULL;
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
        ZCIO_LOG(ERR, "server param error\n");
		goto out_free; 
    }

    // 解析 server-iface 参数
    ret = parse_kvargs(kvlist, ETH_ZCIO_SERVER_IFACE_ARG, &open_iface, &server_iface);
    if(ret < 0) {
        ZCIO_LOG(ERR, "server-iface param error\n");
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
    
    // 解析 memctl-iface 参数
    if (!server) {
        ret = parse_kvargs(kvlist, ETH_ZCIO_MEMCTL_IFACE_ARG, &open_iface, &memctl_iface);
        if(ret < 0) {
            ZCIO_LOG(ERR, "memctl-iface param error\n");
            goto out_free; 
        }
    }
    
	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

	ret = eth_dev_zcio_create(dev, server, queues, memctl_iface,
                dev->device.numa_node, server_iface);
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
    "server-iface=<path>"
    "queues=<int>"
    "memctl-iface=<path>");