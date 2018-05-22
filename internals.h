#pragma once
#include "http_server.h"
#include "queue.h"
#include <apr_pools.h>
#include <stddef.h>
#include <pthread.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* dynamic buffer */
typedef struct {
    char            *data;
    unsigned        size;
    unsigned        capacity;
} dyn_buf;

struct srv_socket {
    ev_io                   io;
    LIST_ENTRY(srv_socket)  link;
    const char              *addr;
};

struct http_server {
    LIST_HEAD(,srv_socket)  srv_sock;
    TAILQ_HEAD(,http_exchange)    rqueue; /* global queue of requests ready to be processed */
    pthread_mutex_t         rq_lock;
    pthread_cond_t          rq_ntfy;
    http_server_request_cb  on_request;
    void                    *on_request_ctx;
};

struct http_ohdr {
    pstr_t                  name;
    pstr_t                  value;
    TAILQ_ENTRY(http_ohdr)  link;
};

struct chunk {
    STAILQ_ENTRY(chunk)     link;
    unsigned                capacity;
    unsigned                len;
    char                    data[0];
};

/* Chain object is used to send long responses: after individual chunk
 * had been sent, it is immediately freed.
 */
struct chain {
    unsigned                c_off;      /* offset for first chunk */
    STAILQ_HEAD(, chunk)    data;
};

struct http_response {
    TAILQ_HEAD(,http_ohdr)  ohdr;       /* Response headers */
    struct chain            out;        /* Output chain */
    char                   *status;     /* status line */
    FILE                   *fout;       /* file "pseudohandle" */
};

typedef struct {
    const char      *data;
    size_t          len;
} phr_str;

#define STRUCT_FROM_FIELD(ptr, type, field) ((type*)((char*)(ptr) - offsetof(type, field)))
#define EX_FROM_RQ(ptr) STRUCT_FROM_FIELD(ptr, struct http_exchange, rq)
#define EX_FROM_RS(ptr) STRUCT_FROM_FIELD(ptr, struct http_exchange, rs)

typedef enum {
    HEST_RECV,                          /**< request is being read from client */
    HEST_ENQUEUED,                      /**< request had been enqueued */
    HEST_PROCESSING,                    /**< request had been picked by http_server_get_request */
    HEST_SUBMITTED,                     /**< request had been submitted */
    HEST_SEND,                          /**< request is being send to client */
} http_ex_state_t;

struct http_exchange {
    apr_pool_t              *pool;      /* memory pool */
    http_request            rq;         /* parsed request */
    http_response           rs;         /* response */
    uint64_t                remaining;  /* remaining bytes */
    dyn_buf                 rqbuf;      /* request buffer. Both headers and body are placed here */
    STAILQ_ENTRY(http_exchange) link;   /* per-connection send queue */
    TAILQ_ENTRY(http_exchange) slink;   /* per-server request queue */
    LIST_ENTRY(http_exchange) clist;    /* list of all active exchange entries per connection */
    http_ex_state_t         state;      /* exchange state */
    ev_async                ntfy;       /* when something in rqueue is ready to be sent */
    struct ev_loop          *loop;      /* for ev_async_send */
};

typedef enum {
    HCST_ACTIVE         = 0,            /* connection is active and receiving requests */
    HCST_CLIENT_EOF     = 1,            /* got EOF from client => no more reads will be
                                         * done from socket */
    HCST_ABORTED        = 2,            /* For aborted connection no attempts to do send/recv
                                         * are done. Object is waiting to be freed after last
                                         * http_exchange from queue will be posted */
} http_conn_state_t;

/* Connection object is responsible for reading new requests
 * and sending enqueued responses. */
struct http_conn {
    ev_io                       rcv;            /* io handler for read operations */
    ev_io                       snd;            /* io handler for write operations */
    struct http_exchange        *rq;            /* request being currently read */
    /* TODO: maybe one TAILQ would be enought? */
    STAILQ_HEAD(,http_exchange) sndq;           /* requests that are ready to be send */
    LIST_HEAD(,http_exchange)   exs;            /* collection of exchange objects belong to this connection */
    http_server                 *srv;           /* server who owns this connection */
    http_conn_state_t           state;          /* got eof from client. This flag is checked when response had been sent.
                                                 * If eof is set, connection will be release when last item from rqueue
                                                 * had been processed. */
};

/* send "100-continue" response (quick & dirty, relaying on socket buffers not being empty */
bool send_100_continue(int fd);
/* send buffer over socket with optional TCP_CORK */
bool sock_send_buf(const void *buf, unsigned len, int fd, bool cork);
/* send string over socket with optional TCP_CORK (wrapper for sock_send_buf) */
bool sock_send_str(const char *msg, int fd, bool cork);

/* send-and-release chain */
void chain_init(struct chain *ch);
/* Send as many chunks as possible. All fully sent chunks are freed. */
ssize_t chain_send(struct chain *ch, int fd);
/* Free all chunks. */
void chain_cleanup(struct chain *ch);
/* Append data to chain */
void chain_append(struct chain *ch, const void *data, unsigned len);
/* Returns length of the chain in bytes. TODO: save it' don't recalculate.  */
uint64_t chain_len(struct chain *ch);
/* create chunk of specified data size */
struct chunk *chunk_new(unsigned size);

/* Build dynamically allocated array of headers */
struct http_ohdr* http_ohdr_new(apr_pool_t *pool, const char *name, const char *value);

void http_response_init(http_response *rs);
/* Release dynamic memory assotiated with request */
void http_request_cleanup(http_request *rq);
/* Generate request identifier */
void assign_request_id(http_request *rq, apr_pool_t *pool);

void http_request_init(http_request *rq);
/* Release dynamic memory assotiated with response */
void http_response_cleanup(http_response *rs);

struct http_exchange *http_exchange_new();
/* Destroy "single request" object releasing all memory */
void http_exchange_free(struct http_exchange *ex);

/* Assign request_id */

/* Resolve & bind */
int make_and_bind_socket(const char *addr, int sockflags);

void dyn_buf_init(dyn_buf *b, unsigned capacity);
int dyn_buf_read(dyn_buf *b, int fd, unsigned len);
void dyn_buf_append(dyn_buf *b, const void *data, unsigned len);
