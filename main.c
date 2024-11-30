#define _GNU_SOURCE
#include <stdio.h>
#include <poll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <malloc.h>
#include "queue.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>

#define FDS_COUNT 100

#define ALLOC_INIT(type, ...)   \
        (type *)memdup((type[]){ __VA_ARGS__ }, sizeof(type))


#define AREAD(fd, buf, size, got) \
	read(fd, ((uint8_t*) buf) + got, size - got)

#define AWRITE(fd, buf, size, wrote) \
	write(fd, ((uint8_t*) buf) + wrote, size - wrote)

#define FREE_TASK(task)    \
	do {                   \
		free(task->state); \
		free(task);        \
        task = NULL;       \
	}while(0);

typedef enum : uint8_t {
	CmdType_CONNECT = 0x01,
	CmdType_BIND = 0x02,
	CmdType_UDP_ASSOCIATE = 0x3
} CmdType;

typedef enum AddressType : uint8_t {
	AddressType_IPV4 = 0x01,
	AddressType_DOMAINNAME = 0x03,
	AddressType_IPV6 = 0x4
} AddressType;

typedef struct SocksReqeust {
	CmdType cmd;
	AddressType type;
	union {
		uint32_t ipv4;
		const char* domain;
	};
	uint16_t port;
}SocksReqeust;

void *memdup(const void *src, size_t sz) {
	void *mem = malloc(sz);
	return mem ? memcpy(mem, src, sz) : NULL;
}

static bool stop = false;

static Queue* task_queue = NULL;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;

static struct pollfd fds[FDS_COUNT] = {0};
static Task* fds_tasks[FDS_COUNT] = {0};
static pthread_mutex_t fds_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void queue_push(Task* task){
	pthread_mutex_lock(&queue_lock);
	enqueue(task_queue, task);
	pthread_mutex_unlock(&queue_lock);
}

static inline void fds_push(Task* task, int fd, short int event) {
	pthread_mutex_lock(&fds_lock);
	int i = 0;
	for(; i < FDS_COUNT; ++i) {
		if (fds[i].fd == 0){
			break;
		}
	}
	
	if(i == FDS_COUNT){
		pthread_mutex_unlock(&fds_lock);
		assert(false);
	}
	
	fds[i].fd = fd;
	fds[i].events = event;
	fds[i].revents = 0;
	fds_tasks[i] = task;
	
	pthread_mutex_unlock(&fds_lock);
	
}

static void sigint() {
	stop = true;
}

static void scheduler() {
	Task *task = NULL;
	while (!stop) {
		pthread_mutex_lock(&queue_lock);
		if(!isEmpty(task_queue))
		{
			task = peek(task_queue);
			dequeue(task_queue);
		}
		pthread_mutex_unlock(&queue_lock);
		
		if(task){
			task->func(task);
			task = NULL;
		}
		
		int ret = poll(fds, FDS_COUNT, 100);
		if (ret < 0){
			printf("poll error: %s\n", strerror(errno));
			continue;
		}
		
		if (ret != 0){
			for(int i = 0; i < FDS_COUNT; ++i) {
				if(fds[i].fd != 0 && fds[i].revents != 0){
					memset(&fds[i], 0, sizeof(fds[i]));
					task = fds_tasks[i];
					fds_tasks[i] = NULL;
					queue_push(task);
				}
			}
		}
	}
}

static Task* auth (Task* task, Task* await_by, int fd) {
	ssize_t ret;
	bool result = false;
	
	const uint8_t init_response[] = {0x5, 0x0};
	
	typedef struct {
		uint8_t version;
		uint8_t auth_methods_count;
	} InitPackage;

	typedef struct {
		uint8_t version;
		uint8_t method;
	} Response;
	
	typedef struct {
		int fd;
		size_t got;
		size_t to_read;
		
		size_t to_write;
		size_t wrote;
		
		InitPackage init_package;
		
		uint8_t* auth_methods;
	} State;
	
	if (task == NULL) {
		task = ALLOC_INIT(Task, {
			.func = (void (*)(struct Task*)) auth,
			.state = ALLOC_INIT(State, {
					.fd = fd
			}),
			.await_by = await_by
		});
		queue_push(task);
		return task;
	}


	State* state = task->state;

	switch(task->step) {
		case 0:
			break;
		case 1:
			goto step1;
		case 2:
			goto step2;
		case 3:
			goto step3;
		default:
			assert(false);
	}

	state->to_read = sizeof(InitPackage);
	state->got = 0;
	while(state->got != state->to_read) {
		step1:
		ret = AREAD(state->fd, &state->init_package, sizeof(InitPackage), state->got);
		if((ret == -1 && errno == EAGAIN)) {
			task->step = 1;
			fds_push(task, state->fd, POLLIN);
			return NULL;
		}
		state->got += ret;
	}
	
	printf("version: %d\n", state->init_package.version);

	state->auth_methods = malloc(sizeof(uint8_t) * state->init_package.auth_methods_count);

	state->to_read = sizeof(uint8_t) * state->init_package.auth_methods_count;
	state->got = 0;
	while(state->got != state->to_read) {
		step2:
		ret = AREAD(state->fd, state->auth_methods, sizeof(InitPackage), state->got);
		if((ret == -1 && errno == EAGAIN)) {
			task->step = 2;
			fds_push(task, state->fd, POLLIN);
			return NULL;
		}
		state->got += ret;
	}

	bool has_no_auth = false;
	for(int i = 0; i < state->init_package.auth_methods_count; ++i) {
		if(state->auth_methods[i] == 0){
			has_no_auth = true;
			break;
		}
	}
	if (!has_no_auth){
		result = false;
		goto end;
	}
	
	state->to_write = sizeof(init_response);
	state->wrote = 0;
	while(state->wrote != state->to_write) {
		step3:
		ret = AWRITE(state->fd, init_response, sizeof(InitPackage), state->wrote);
		if((ret == -1 && errno == EAGAIN)) {
			task->step = 3;
			fds_push(task, state->fd, POLLOUT);
			return NULL;
		}
		state->wrote += ret;
	}
	
	result = true;
	
	end:
	if(task->await_by == NULL){
		FREE_TASK(task);
	}else{
		task->result.data = result;
		queue_push(task->await_by);
	}
	return NULL;
}

static Task* get_request(Task* task, Task* await_by, int fd){
	
	ssize_t ret;
	
	typedef struct {
		uint8_t version;
		CmdType cmd;

		uint8_t rsv;
		AddressType address_type;
	} __attribute__((packed)) SOCKS5requestBase;

	typedef struct {
		int fd;

		SOCKS5requestBase request_base;
		union {
			uint32_t ipv4;
			const char* domain;
		};
		
		uint16_t port;
		
		size_t to_read;
		size_t got;
	} State;

	if (task == NULL) {
		task = ALLOC_INIT(Task, {
			.func = (void (*)(struct Task*)) get_request,
			.state = ALLOC_INIT(State, {
					.fd = fd
			}),
			.await_by = await_by
		});
		queue_push(task);
		return task;
	}

	State* state = task->state;
	
	switch(task->step) {
		case 0:
			break;
		case 1:
			goto step1;
		case 2:
			goto step2;
		case 3:
			goto step3;
		default:
			assert(false);
	}

	state->to_read = sizeof(SOCKS5requestBase);
	state->got = 0;
	while(state->got != state->to_read) {
		step1:
		ret = AREAD(state->fd, &state->request_base, sizeof(SOCKS5requestBase), state->got);
		if(ret == -1 && errno == EAGAIN) {
			task->step = 1;
			fds_push(task, state->fd, POLLIN);
			return NULL;
		}else if (ret == -1) {
			const char* err = strerror(errno);
			printf("%s\n",err);
			return NULL;
		}
		
		state->got += ret;
	}
	
	if (state->request_base.address_type == AddressType_IPV4)
	{
		state->to_read = sizeof(state->ipv4);
		state->got = 0;
		while(state->got != state->to_read) {
			step2:
			ret = AREAD(state->fd, &state->ipv4, sizeof(state->ipv4), state->got);
			if(ret == -1 && errno == EAGAIN) {
				task->step = 2;
				fds_push(task, state->fd, POLLIN);
				return NULL;
			}else if (ret == -1) {
				const char* err = strerror(errno);
				printf("%s\n",err);
				return NULL;
			}

			state->got += ret;
		}
	}

	state->to_read = sizeof(state->port);
	state->got = 0;
	while(state->got != state->to_read) {
		step3:
		ret = AREAD(state->fd, &state->port, sizeof(state->port), state->got);
		if(ret == -1 && errno == EAGAIN) {
			task->step = 3;
			fds_push(task, state->fd, POLLIN);
			return NULL;
		}else if (ret == -1) {
			const char* err = strerror(errno);
			printf("%s\n",err);
			return NULL;
		}

		state->got += ret;
	}
	
	if(task->await_by == NULL){
		FREE_TASK(task);
	}else {
		task->result.ptr = (intptr_t) ALLOC_INIT(SocksReqeust, {
			.cmd = state->request_base.cmd,
			.type = state->request_base.address_type,
			.ipv4 = state->ipv4,
			.port = state->port,
		});
		queue_push(task->await_by);
	}
	
	return NULL;
}

static Task* read_from_target(Task* task, Task* await_by, int target_fd, int client_fd)
{
	typedef struct {
		int target_fd;
		int client_fd;
		
		size_t to_write;
		ssize_t wrote;
		
		uint8_t buffer[1024];
	} State;

	if (task == NULL) {
		task = ALLOC_INIT(Task, {
			.func = (void (*)(struct Task*)) read_from_target,
			.state = ALLOC_INIT(State, {
					.target_fd = target_fd,
					.client_fd = client_fd,
			}),
			.await_by = await_by
		});
		queue_push(task);
		return task;
	}
	
	State* state = task->state;

	switch(task->step) {
		case 0:
			goto step0;
		case 1:
			goto step1;
		default:
			assert(false);
	}

	while(true) {
	step0:
		ssize_t ret = read(state->target_fd, state->buffer,
						   sizeof(state->buffer));
		if(ret == -1 && errno == EAGAIN) {
			task->step = 0;
			fds_push(task, state->target_fd, POLLIN);
			return NULL;
		}else if(ret == -1) {
			printf("%s:%d - %s\n", __func__, __LINE__, strerror(errno));
			return NULL;
		}else if(ret == 0){
			printf("EOF\n");
			return NULL;
		}
		printf("%s:%d - ret: %zd\n", __func__, __LINE__, ret);
		
		state->to_write = ret;
		state->wrote = 0;
		while(state->wrote != state->to_write) {
		step1:
			ret = AWRITE(state->client_fd, state->buffer, state->to_write,
						 state->wrote);
			if((ret == -1 && errno == EAGAIN)) {
				task->step = 1;
				fds_push(task, state->client_fd, POLLOUT);
				return NULL;
			}else if(ret == -1) {
				printf("%s:%d - %s\n", __func__, __LINE__, strerror(errno));
				return NULL;
			}else if (ret == 0){
				printf("EOF\n");
				return NULL;
			}

			state->wrote += ret;
		}
	}

}

static Task* socks5_connect(Task* task, Task* await_by, int fd, SocksReqeust* reqeust) {
	typedef struct ConnectResponse {
		uint8_t version;
		uint8_t response;
		uint8_t rsv;
		AddressType address_type;
		uint32_t address;
		uint16_t port;
	} __attribute__((packed)) ConnectResponse;
	
	typedef struct {
		int fd;
		SocksReqeust* reqeust;
		int sock_fd;

		ConnectResponse connect_response;
		
		size_t to_read;
		size_t got;
		
		size_t to_write;
		size_t wrote;
		
		uint8_t buffer[1023];
	} State;

	if (task == NULL) {
		task = ALLOC_INIT(Task, {
			.func = (void (*)(struct Task*)) socks5_connect,
			.state = ALLOC_INIT(State, {
					.fd = fd,
					.reqeust = reqeust,
			}),
			.await_by = await_by
		});
		queue_push(task);
		return task;
	}
	
	State* state = task->state;

	switch(task->step) {
		case 0:
			break;
		case 1:
			goto step1;
		case 2:
			goto step2;
		case 3:
			goto step3;
		case 4:
			goto step4;
		default:
			assert(false);
	}
	
	struct sockaddr_in servaddr;

	// socket create and verification
	state->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (state->sock_fd == -1) {
		printf("socket creation failed...\n");
		return NULL;
	}
	else
		printf("Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = state->reqeust->ipv4;
	servaddr.sin_port = state->reqeust->port;
	struct in_addr ip_addr;
	ip_addr.s_addr = state->reqeust->ipv4;
	printf("connecting to %s:%d\n", inet_ntoa(ip_addr), htons(state->reqeust->port));

	int c_ret = connect(state->sock_fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	
	if (c_ret == -1 && errno == EINPROGRESS){
		task->step = 1;
		fds_push(task, state->fd, POLLOUT);
		return NULL;
	}else if (c_ret == -1) {
		int test = errno;
		printf("connection with the server failed... %s\n", strerror(test));
		return NULL;
	}

	step1:
	state->connect_response.version = 0x5;
	state->connect_response.response = 0x0;
	state->connect_response.rsv = 0x0;
	state->connect_response.address_type = AddressType_IPV4;
	state->connect_response.address = state->reqeust->ipv4;
	state->connect_response.port = state->reqeust->port;
	
	state->to_write = sizeof(state->connect_response);
	state->wrote = 0;
	while(state->wrote != state->to_write) {
		step2:
		ssize_t ret = AWRITE(state->fd, &state->connect_response, state->to_write,
							 state->wrote);
		if((ret == -1 && errno == EAGAIN)) {
			task->step = 2;
			fds_push(task, state->fd, POLLOUT);
			return NULL;
		}else if(ret == -1) {
			printf("%s:%d - %s\n", __func__, __LINE__, strerror(errno));
			return NULL;
		}else if(ret == 0){
			printf("EOF\n");
			goto end;
		}
		state->wrote += ret;
	}

	read_from_target(NULL, NULL, state->sock_fd, state->fd);

	while(true) {
		step3:
		ssize_t ret = read(state->fd, state->buffer, sizeof(state->buffer));
		if(ret == -1 && errno == EAGAIN) {
			task->step = 3;
			fds_push(task, state->fd, POLLIN);
			return NULL;
		}else if(ret == -1) {
			printf("%s:%d - %s\n", __func__, __LINE__, strerror(errno));
			goto end;
		}else if(ret == 0){
			printf("EOF");
			goto end;
		}

		state->to_write = ret;
		state->wrote = 0;
		while(state->wrote != state->to_write) {
			step4:
			ret = AWRITE(state->sock_fd, state->buffer, state->to_write, state->wrote);
			if((ret == -1 && errno == EAGAIN)) {
				task->step = 4;
				fds_push(task, state->sock_fd, POLLOUT);
				return NULL;
			}else if(ret == -1) {
				printf("%s:%d - %s\n", __func__, __LINE__, strerror(errno));
				goto end;
			}

			state->wrote += ret;
		}
	}
	end:
	if (task->await_by){
		queue_push(task->await_by);
	}else{
		FREE_TASK(task);
	}
	
	return NULL;
}

static Task* process_client(Task* task, Task* await_by, int fd) {
	typedef struct {
		int fd;
		Task* auth_result;
		Task* request_result;
		Task* connect_result;
	} State;

	if (task == NULL) {
		task = ALLOC_INIT(Task, {
			.func = (void (*)(struct Task*)) process_client,
			.state = ALLOC_INIT(State, {
				.fd = fd
			}),
			.await_by = await_by
		});
		queue_push(task);
		return task;
	}
	
	State* state = task->state;
	switch(task->step) {
		case 0:
			break;
		case 1:
			goto step1;
		case 2:
			goto step2;
		case 3:
			goto step3;
		default:
			assert(false);
	}

	state->auth_result = auth(NULL, task, state->fd);
	task->step = 1;
	return NULL;
step1:
	
	bool is_auth_ok = state->auth_result->result.data;
	FREE_TASK(state->auth_result);
	if (!is_auth_ok){
		goto end;
	}
	
	state->request_result = get_request(NULL, task, state->fd);
	task->step = 2;
	return NULL;
step2:
	
	SocksReqeust* socksReqeust = (SocksReqeust*) state->request_result->result.ptr;
	FREE_TASK(state->request_result);
	
	if(socksReqeust->cmd == CmdType_CONNECT){
		socks5_connect(NULL, task, state->fd, socksReqeust);
		task->step = 3;
		return NULL;
	}
step3:
	
	end:
	printf("client disconnect\n");
	close(state->fd);
	if(task->await_by == NULL){
		FREE_TASK(task);
	}else{
		queue_push(task->await_by);
	}
	return NULL;
}

int main(void) {

	signal(SIGINT, (__sighandler_t) sigint);

	task_queue = malloc(sizeof(Queue));
	initializeQueue(task_queue);

	pthread_t scheduler_thread;
	
	pthread_create(&scheduler_thread, NULL, (void* (*)(void*)) scheduler, NULL);
	
	struct sockaddr_in servaddr;
	int sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		return -1;
	}
	int flags = fcntl(sockfd, F_GETFL, 0);
	if (flags == -1) return -1;
	flags &= ~O_NONBLOCK;
	fcntl(sockfd, F_SETFL, flags);

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(10000);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	if ((bind(sockfd, (const struct sockaddr *)& servaddr, sizeof(servaddr))) != 0) {
		printf("socket bind failed... %s\n", strerror(errno));
		return -1;
	}
	else
		printf("Socket successfully binded..\n");

	if ((listen(sockfd, 5)) != 0) {
		printf("Listen failed...\n");
		return -1;
	}
	else
		printf("Server listening..\n");

	while(!stop)
	{
		struct sockaddr client_addr;
		socklen_t size;
		int client_fd = accept4(sockfd, &client_addr, &size, SOCK_NONBLOCK);
		process_client(NULL, NULL, client_fd);
	}

	pthread_join(scheduler_thread, NULL);

	printf("stop\n");
	
	return 0;
}
