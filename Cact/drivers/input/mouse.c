#include "mouse.h"
#include "fb.h"

// Global mouse state — read by userspace GUI or terminal
volatile int mouse_x       = 0;
volatile int mouse_y       = 0;
volatile int mouse_buttons = 0;

// Circular buffer for mouse events — single-producer (IRQ) / single-consumer (userspace)
static volatile mouse_packet_t mouse_buf[MOUSE_BUF_SIZE];
static volatile uint32_t   mouse_wr = 0;   // IRQ handler writes here
static volatile uint32_t   mouse_rd = 0;   // userspace reads here

// Dequeue one mouse event; returns 0 on success, -1 if buffer is empty.
int mouse_read_event(mouse_packet_t *pkt) {
    if (mouse_rd == mouse_wr) return -1;
    __asm__ __volatile__("" ::: "memory");   // barrier: read data after reading mouse_wr
    *pkt = mouse_buf[mouse_rd];
    mouse_rd = (mouse_rd + 1) % MOUSE_BUF_SIZE;
    return 0;
}