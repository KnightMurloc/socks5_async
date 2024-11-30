//
// Created by victor on 24.11.24.
//

#ifndef SOCKS5_ASYNC_TASK_H
#define SOCKS5_ASYNC_TASK_H

#include <stdint.h>

typedef struct Task {
	void (*func)(struct Task*);
	void* state;
	int step;
	struct Task* await_by;
	union {
		uintptr_t ptr;
		uint64_t data;
	} result;
} Task;

#endif //SOCKS5_ASYNC_TASK_H
