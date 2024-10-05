/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _FD_MAN_H_
#define _FD_MAN_H_
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>

#define MAX_FDS 1024

typedef void (*fd_cb)(int fd, void *dat, int *remove);

struct fdentry {
	int fd;		/* -1 indicates this entry is empty */
	fd_cb rcb;	/* callback when this fd is readable. */
	fd_cb wcb;	/* callback when this fd is writeable.*/
	void *dat;	/* fd context */
	int busy;	/* whether this entry is being used in cb. */
};

struct fd_set {
	struct pollfd rwfds[MAX_FDS];
	struct fdentry fd[MAX_FDS];
	pthread_mutex_t fd_mutex;
	pthread_mutex_t fd_pooling_mutex;
	int num;	/* current fd number of this fd_set */

	union pipefds {
		struct {
			int pipefd[2];
		};
		struct {
			int readfd;
			int writefd;
		};
	} u;

	pthread_mutex_t sync_mutex;
	pthread_cond_t sync_cond;
	bool sync;
};


void fd_set_init(struct fd_set *pfd_set);

int fd_set_add(struct fd_set *pfd_set, int fd,
	fd_cb rcb, fd_cb wcb, void *dat);

void *fd_set_del(struct fd_set *pfd_set, int fd);
int fd_set_try_del(struct fd_set *pfd_set, int fd);

uint32_t fd_set_event_dispatch(void *arg);

int fd_set_pipe_init(struct fd_set *fd_set);

void fd_set_pipe_uninit(struct fd_set *fd_set);

void fd_set_pipe_notify(struct fd_set *fd_set);
void fd_set_pipe_notify_sync(struct fd_set *fd_set);

#endif
