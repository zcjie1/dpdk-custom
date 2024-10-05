
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <rte_log.h>
#include <rte_bus_vdev.h>
#include <rte_kvargs.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <bus_vdev_driver.h>

#include "zcio.h"

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
	struct rte_eth_conf *dev_conf = &eth_dev->data->dev_conf;
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
	rte_atomic32_set(&internal->started, 0);

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
	unsigned int i, ret;

	internal = dev->data->dev_private;
	if (!internal)
		return 0;

	ret = eth_dev_stop(dev);

	rte_free(internal->server_iface);
	rte_free(internal->memctl_iface);
	rte_free(internal);


	dev->data->dev_private = NULL;

	return ret;
}

static void
zcio_msg_handler(int client_fd, void *dat, int *remove) {
	return;
}

static void
zcio_server_new_connection(int listen_fd, void *dat, int *remove __rte_unused)
{
	struct rte_eth_dev *dev = dat;
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_socket *client_sock = &(internal->unix_sock[TYPE_SERVER_2_CLIENT]);
	int client_fd;
	int ret;

	client_fd = accept(listen_fd, (struct sockaddr *)&client_sock->un, 
						sizeof(struct sockaddr_un));
	if (client_fd < 0)
		return;

	ZCIO_LOG(INFO, "[%s] new zcio connection is %d\n",internal->server_iface, listen_fd);
	ret = fdset_add(&internal->fdset, client_fd, zcio_msg_handler,
			NULL, &(internal->unix_sock[TYPE_SERVER_2_CLIENT]));
	if (ret < 0) {
		ZCIO_LOG(ERR, "[%s] failed to add fd %d into zcio server fdset\n", 
					internal->server_iface, client_fd);
		close(client_fd);
		return;
	}
	
	client_sock->sock_fd = client_fd;
	rte_atomic32_set(&internal->attched, 1);
	fdset_del(&internal->fdset, listen_fd);
	close(listen_fd);

	fdset_pipe_notify(&internal->fdset);
}

static int
zcio_start_server(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	struct zcio_socket *sock = NULL;
	struct sockaddr_un *un = NULL;
	int fd = 0;
	int ret = 0;
	
	ZCIO_LOG(INFO, "server mode configure\n");
	sock = &(internal->unix_sock[TYPE_SERVER_LISTENER]);
	
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto out;
	
	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if(ret < 0) {
		ZCIO_LOG(ERR, "failed to set fd to non-blocking mode\n");
		goto out_free_fd;
	}
	
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
	ZCIO_LOG(INFO, "binding succeeded\n");

	ret = listen(fd, 4);
	if (ret < 0)
		goto out_free_fd;
	
	ret = fdset_add(&internal->fdset, fd, zcio_server_new_connection,
		  NULL, dev);
	if (ret < 0) {
		ZCIO_LOG(ERR, "failed to add listen fd %d to zcio server fdset\n",
			fd);
		goto out_free_fd;
	}

 out_free_fd:
	close(fd);

 out:
	return -1;
}

static int
zcio_start_client(struct rte_eth_dev *dev)
{
	return 0;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	int ret;
	
	// 创建轮询线程，处理文件描述符集合的读写回调函数
	static rte_thread_t fdset_tid;
	if (fdset_tid.opaque_id == 0) {
		if (fdset_pipe_init(&internal->fdset) < 0) {
			ZCIO_LOG(ERR, "failed to create pipe for zcio fdset\n");
			return -1;
		}

		int ret = rte_thread_create_internal_control(&fdset_tid,
				"zcio-evt", fdset_event_dispatch, &internal->fdset);
		if (ret != 0) {
			ZCIO_LOG(ERR, "failed to create fdset handling thread\n");
			fdset_pipe_uninit(&internal->fdset);
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
zcio_dev_priv_dump(struct rte_eth_dev *dev, FILE *f)
{
	struct pmd_internal *internal = dev->data->dev_private;

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

static uint16_t
eth_zcio_server_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	return 0;
}

static uint16_t
eth_zcio_server_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	return 0;
}

static uint16_t
eth_zcio_client_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	return 0;
}

static uint16_t
eth_zcio_client_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	return 0;
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

	ZCIO_LOG(INFO, "Creating ZCIO driver on numa socket %u\n",
		numa_node);

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
	data->dev_flags = RTE_ETH_DEV_INTR_LSC;
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
    
    ret = rte_kvargs_process(kvlist, key_match, &handler, opaque);
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
	struct rte_eth_dev *eth_dev;
	const char *name = rte_vdev_device_name(dev);

	ZCIO_LOG(INFO, "Initializing pmd_zcio for %s\n", name);

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
	if (kvlist == NULL)
		return -1;

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
    ret = parse_kvargs(kvlist, ETH_ZCIO_QUEUES_ARG, &open_int, &queues);
    if(ret < 0) {
        ZCIO_LOG(ERR, "queues param error\n");
		queues = 1; 
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

	ret = eth_dev_zcio_create(dev, server, memctl_iface, queues,
                dev->device.numa_node, server_iface);
	if (ret < 0)
		ZCIO_LOG(ERR, "Failed to create %s\n", name);

 out_free:
	rte_kvargs_free(kvlist);
	return ret;
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