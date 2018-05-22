#pragma once

typedef struct {
    char        *data;
    unsigned    len;
} pstr_t;

#define PSTR_UDATA(ps) ((unsigned char*)(ps)->data)

/* compare pstr_t* against compile-time constant string */
#define PSTR_EQ_C(ps, cs) ((ps)->len == sizeof(cs) - 1 && memcmp((ps)->data, cs, sizeof(cs) - 1) == 0)
/* case-insensitive compare */
#define PSTR_CASEEQ_C(ps, cs) ((ps)->len == sizeof(cs) - 1 && strncasecmp((ps)->data, cs, sizeof(cs) - 1) == 0)
