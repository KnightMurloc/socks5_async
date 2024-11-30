//
// Created by victor on 24.11.24.
//

#include "queue.h"
#include <stdio.h>



// Function to initialize the queue
void initializeQueue(Queue* q)
{
	q->front = -1;
	q->rear = 0;
}

// Function to check if the queue is empty
bool isEmpty(Queue* q) { return (q->front == q->rear - 1); }

// Function to check if the queue is full
bool isFull(Queue* q) { return (q->rear == MAX_SIZE); }

// Function to add an element to the queue (Enqueue
// operation)
void enqueue(Queue* q, Task* value)
{
	if (isFull(q)) {
		printf("Queue is full\n");
		return;
	}
	q->items[q->rear] = value;
	q->rear++;
}

// Function to remove an element from the queue (Dequeue
// operation)
void dequeue(Queue* q)
{
	if (isEmpty(q)) {
		printf("Queue is empty\n");
		return;
	}
	q->front++;
}

// Function to get the element at the front of the queue
// (Peek operation)
Task* peek(Queue* q)
{
	if (isEmpty(q)) {
		printf("Queue is empty\n");
		return NULL; // return some default value or handle
		// error differently
	}
	return q->items[q->front + 1];
}