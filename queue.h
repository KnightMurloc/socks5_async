//
// Created by victor on 24.11.24.
//

#ifndef SOCKS5_ASYNC_QUEUE_H
#define SOCKS5_ASYNC_QUEUE_H
#include "task.h"
#include <stdbool.h>
#define MAX_SIZE 100


// Defining the Queue structure
typedef struct {
	Task* items[MAX_SIZE];
	int front;
	int rear;
} Queue;

void initializeQueue(Queue* q);
bool isEmpty(Queue* q);
bool isFull(Queue* q);
void enqueue(Queue* q, Task* value);
void dequeue(Queue* q);
Task* peek(Queue* q);
#endif //SOCKS5_ASYNC_QUEUE_H
