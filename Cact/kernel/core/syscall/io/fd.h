#ifndef SC_FD_H
#define SC_FD_H

#include "kernel.h"
#include "task.h"
#include "vfs.h"
#include "mod.h"

// fcntl flag for non-blocking mode
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x0800
#endif

// poll() event flags
#define POLLIN   0x0001
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020

struct pollfd {
    int   fd;
    short events;
    short revents;
};

// Directory entry structure for getdents()
struct cact_dirent {
    uint32_t d_ino;
    char     d_name[124];
};

// File descriptor syscalls
sysret_t sys_open(char* name, int flags);
sysret_t sys_read(int fd, char* buf, unsigned int size);
sysret_t sys_write(int fd, char* buf, unsigned int size);
sysret_t sys_close(int fd);
sysret_t sys_ioctl(struct syscall_frame* regs);
int sys_fcntl(int fd, int cmd, int arg);
int sys_dup(int oldfd);
sysret_t sys_poll(struct syscall_frame* regs);

// Shared fd-table lookup (fd.c), used by the mux syscalls too.
file_t *_get_file(int fd);

#endif 