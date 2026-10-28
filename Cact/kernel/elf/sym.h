#ifndef SYM_H
#define SYM_H

#include <stdint.h>

const char* sym_resolve_addr(uint64_t addr, uint64_t* offset);

#endif
