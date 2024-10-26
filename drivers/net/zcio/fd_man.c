/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>

#include "fd_man.h"

RTE_LOG_REGISTER_DEFAULT(fdset_logtype, INFO);

#define FDMAN_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, fdset_logtype, fmt, ##args)

#define FDPOLLERR (POLLERR | POLLHUP | POLLNVAL)

static int
get_last_valid_idx(struct fd_set *pfd_set, int last_valid_idx)
{
	int i;

	for (i = last_valid_idx; i >= 0 && pfd_set->fd[i].fd == -1; i--)
		;

	return i;
}

static void
fd_set_move(struct fd_set *pfd_set, int dst, int src)
{
	pfd_set->fd[dst]    = pfd_set->fd[src];
	pfd_set->rwfds[dst] = pfd_set->rwfds[src];
}

static void
fd_set_shrink_nolock(struct fd_set *pfd_set)
{
	int i;
	int last_valid_idx = get_last_valid_idx(pfd_set, pfd_set->num - 1);

	for (i = 0; i < last_valid_idx; i++) {
		if (pfd_set->fd[i].fd != -1)
			continue;

		fd_set_move(pfd_set, i, last_valid_idx);
		last_valid_idx = get_last_valid_idx(pfd_set, last_valid_idx - 1);
	}
	pfd_set->num = last_valid_idx + 1;
}

/*
 * Find deleted fd entries and remove them
 */
static void
fd_set_shrink(struct fd_set *pfd_set)
{
	pthread_mutex_lock(&pfd_set->fd_mutex);
	fd_set_shrink_nolock(pfd_set);
	pthread_mutex_unlock(&pfd_set->fd_mutex);
}

/**
 * Returns the index in the fd_set for a given fd.
 * @return
 *   index for the fd, or -1 if fd isn't in the fd_set.
 */
static int
fd_set_find_fd(struct fd_set *pfd_set, int fd)
{
	int i;

	for (i = 0; i < pfd_set->num && pfd_set->fd[i].fd != fd; i++)
		;

	return i == pfd_set->num ? -1 : i;
}

static void
fd_set_add_fd(struct fd_set *pfd_set, int idx, int fd,
	fd_cb rcb, fd_cb wcb, void *dat)
{
	struct fdentry *pfdentry = &pfd_set->fd[idx];
	struct pollfd *pfd = &pfd_set->rwfds[idx];

	pfdentry->fd  = fd;
	pfdentry->rcb = rcb;
	pfdentry->wcb = wcb;
	pfdentry->dat = dat;

	pfd->fd = fd;
	pfd->events  = rcb ? POLLIN : 0;
	pfd->events |= wcb ? POLLOUT : 0;
	pfd->revents = 0;
}

void
fd_set_init(struct fd_set *pfd_set)
{
	int i;

	if (pfd_set == NULL)
		return;

	for (i = 0; i < MAX_FDS; i++) {
		pfd_set->fd[i].fd = -1;
		pfd_set->fd[i].dat = NULL;
	}
	pfd_set->num = 0;
}

/**
 * Register the fd in the fd_set with read/write handler and context.
 */
int
fd_set_add(struct fd_set *pfd_set, int fd, fd_cb rcb, fd_cb wcb, void *dat)
{
	int i;

	if (pfd_set == NULL || fd == -1)
		return -1;

	pthread_mutex_lock(&pfd_set->fd_mutex);
	i = pfd_set->num < MAX_FDS ? pfd_set->num++ : -1;
	if (i == -1) {
		pthread_mutex_lock(&pfd_set->fd_pooling_mutex);
		fd_set_shrink_nolock(pfd_set);
		pthread_mutex_unlock(&pfd_set->fd_pooling_mutex);
		i = pfd_set->num < MAX_FDS ? pfd_set->num++ : -1;
		if (i == -1) {
			pthread_mutex_unlock(&pfd_set->fd_mutex);
			return -2;
		}
	}

	fd_set_add_fd(pfd_set, i, fd, rcb, wcb, dat);
	pthread_mutex_unlock(&pfd_set->fd_mutex);

	return 0;
}

/**
 *  Unregister the fd from the fd_set.
 *  Returns context of a given fd or NULL.
 */
void *
fd_set_del(struct fd_set *pfd_set, int fd)
{
	int i;
	void *dat = NULL;

	if (pfd_set == NULL || fd == -1)
		return NULL;

	do {
		pthread_mutex_lock(&pfd_set->fd_mutex);

		i = fd_set_find_fd(pfd_set, fd);
		if (i != -1 && pfd_set->fd[i].busy == 0) {
			/* busy indicates r/wcb is executing! */
			dat = pfd_set->fd[i].dat;
			pfd_set->fd[i].fd = -1;
			pfd_set->fd[i].rcb = pfd_set->fd[i].wcb = NULL;
			pfd_set->fd[i].dat = NULL;
			i = -1;
		}
		pthread_mutex_unlock(&pfd_set->fd_mutex);
	} while (i != -1);

	return dat;
}

/**
 *  Unregister the fd from the fd_set.
 *
 *  If parameters are invalid, return directly -2.
 *  And check whether fd is busy, if yes, return -1.
 *  Otherwise, try to delete the fd from fd_set and
 *  return true.
 */
int
fd_set_try_del(struct fd_set *pfd_set, int fd)
{
	int i;

	if (pfd_set == NULL || fd == -1)
		return -2;

	pthread_mutex_lock(&pfd_set->fd_mutex);
	i = fd_set_find_fd(pfd_set, fd);
	if (i != -1 && pfd_set->fd[i].busy) {
		pthread_mutex_unlock(&pfd_set->fd_mutex);
		return -1;
	}

	if (i != -1) {
		pfd_set->fd[i].fd = -1;
		pfd_set->fd[i].rcb = pfd_set->fd[i].wcb = NULL;
		pfd_set->fd[i].dat = NULL;
	}

	pthread_mutex_unlock(&pfd_set->fd_mutex);
	return 0;
}

/**
 * This functions runs in infinite blocking loop until there is no fd in
 * pfd_set. It calls corresponding r/w handler if there is event on the fd.
 *
 * Before the callback is called, we set the flag to busy status; If other
 * thread(now rte_vhost_driver_unregister) calls fd_set_del concurrently, it
 * will wait until the flag is reset to zero(which indicates the callback is
 * finished), then it could free the context after fd_set_del.
 */
uint32_t
fd_set_event_dispatch(void *arg)
{
	int i;
	struct pollfd *pfd;
	struct fdentry *pfdentry;
	fd_cb rcb, wcb;
	void *dat;
	int fd, numfds;
	int remove1, remove2;
	int need_shrink;
	struct fd_set *pfd_set = arg;
	int val;

	if (pfd_set == NULL)
		return 0;
	
	// static uint64_t event_num;

	while (1) {

		/*
		 * When poll is blocked, other threads might unregister
		 * listenfds from and register new listenfds into fd_set.
		 * When poll returns, the entries for listenfds in the fd_set
		 * might have been updated. It is ok if there is unwanted call
		 * for new listenfds.
		 */
		pthread_mutex_lock(&pfd_set->fd_mutex);
		numfds = pfd_set->num;
		pthread_mutex_unlock(&pfd_set->fd_mutex);

		pthread_mutex_lock(&pfd_set->fd_pooling_mutex);
		val = poll(pfd_set->rwfds, numfds, 1000 /* millisecs */);
		pthread_mutex_unlock(&pfd_set->fd_pooling_mutex);
		if (val < 0)
			continue;

		need_shrink = 0;
		for (i = 0; i < numfds; i++) {
			pthread_mutex_lock(&pfd_set->fd_mutex);

			pfdentry = &pfd_set->fd[i];
			fd = pfdentry->fd;
			pfd = &pfd_set->rwfds[i];

			if (fd < 0) {
				need_shrink = 1;
				pthread_mutex_unlock(&pfd_set->fd_mutex);
				continue;
			}

			if (!pfd->revents) {
				pthread_mutex_unlock(&pfd_set->fd_mutex);
				continue;
			}

			// printf("Recevice %lu poll events\n", ++event_num);

			remove1 = remove2 = 0;

			rcb = pfdentry->rcb;
			wcb = pfdentry->wcb;
			dat = pfdentry->dat;
			pfdentry->busy = 1;

			pthread_mutex_unlock(&pfd_set->fd_mutex);

			if (rcb && pfd->revents & (POLLIN | FDPOLLERR))
				rcb(fd, dat, &remove1);
			if (wcb && pfd->revents & (POLLOUT | FDPOLLERR))
				wcb(fd, dat, &remove2);
			pfdentry->busy = 0;
			/*
			 * fd_set_del needs to check busy flag.
			 * We don't allow fd_set_del to be called in callback
			 * directly.
			 */
			/*
			 * When we are to clean up the fd from fd_set,
			 * because the fd is closed in the cb,
			 * the old fd val could be reused by when creates new
			 * listen fd in another thread, we couldn't call
			 * fd_set_del.
			 */
			if (remove1 || remove2) {
				pfdentry->fd = -1;
				need_shrink = 1;
			}
		}

		if (need_shrink)
			fd_set_shrink(pfd_set);
	}

	return 0;
}

static void
fd_set_pipe_read_cb(int readfd, void *dat,
		   int *remove __rte_unused)
{
	char charbuf[16];
	struct fd_set *fd_set = dat;
	int r = read(readfd, charbuf, sizeof(charbuf));
	/*
	 * Just an optimization, we don't care if read() failed
	 * so ignore explicitly its return value to make the
	 * compiler happy
	 */
	RTE_SET_USED(r);

	pthread_mutex_lock(&fd_set->sync_mutex);
	fd_set->sync = true;
	pthread_cond_broadcast(&fd_set->sync_cond);
	pthread_mutex_unlock(&fd_set->sync_mutex);
}

void
fd_set_pipe_uninit(struct fd_set *fd_set)
{
	fd_set_del(fd_set, fd_set->u.readfd);
	close(fd_set->u.readfd);
	close(fd_set->u.writefd);
}

int
fd_set_pipe_init(struct fd_set *fd_set)
{
	int ret;

	if (pipe(fd_set->u.pipefd) < 0) {
		FDMAN_LOG(ERR,
			"failed to create pipe for zcio fd_set\n");
		return -1;
	}

	ret = fd_set_add(fd_set, fd_set->u.readfd,
			fd_set_pipe_read_cb, NULL, fd_set);

	if (ret < 0) {
		FDMAN_LOG(ERR,
			"failed to add pipe readfd %d into zcio server fd_set\n",
			fd_set->u.readfd);

		fd_set_pipe_uninit(fd_set);
		return -1;
	}

	return 0;
}

void
fd_set_pipe_notify(struct fd_set *fd_set)
{
	int r = write(fd_set->u.writefd, "1", 1);
	/*
	 * Just an optimization, we don't care if write() failed
	 * so ignore explicitly its return value to make the
	 * compiler happy
	 */
	RTE_SET_USED(r);
}

void
fd_set_pipe_notify_sync(struct fd_set *fd_set)
{
	pthread_mutex_lock(&fd_set->sync_mutex);

	fd_set->sync = false;
	fd_set_pipe_notify(fd_set);

	while (!fd_set->sync)
		pthread_cond_wait(&fd_set->sync_cond, &fd_set->sync_mutex);

	pthread_mutex_unlock(&fd_set->sync_mutex);
}
