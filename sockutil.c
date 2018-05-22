#include "internals.h"
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <netinet/tcp.h>

/* addr can be prefixed with "unix:" to allow Unix domain socket creation */
int
make_and_bind_socket(const char *addr, int sockflags)
{
    int sock = -1;

    if (strncmp(addr, "unix:", 5) == 0) {
        fprintf(stderr, "unix address family is not supported yet\n");
    } else {
        int err;
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        char buf[strlen(addr) + 1], *h = buf, *p;

        strcpy(buf, addr);
        p = strrchr(buf, ':');
        if (p == NULL) {
            p = buf;
            h = NULL;
        } else {
            *p++ = 0;
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;      /* no ipv6 please */
        hints.ai_socktype = SOCK_STREAM;

        err = getaddrinfo(h, p, &hints, &result);
        if (err != 0) {
            fprintf(stderr, "getaddrinfo(%s): %s\n", addr, gai_strerror(err));
            return -1;
        }

        err = EINVAL;
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            sock = socket(rp->ai_family, rp->ai_socktype | sockflags, rp->ai_protocol);
            if (sock == -1)
                continue;

            /* Activate SO_REUSEADDR */
            err = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &err, sizeof(err)) != 0)
                fprintf(stderr, "setsockopt(SO_REUSEADDR) failed: %s (ignored)\n", strerror(errno));

            if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
                break;
            err = errno;

            close(sock);
        }

        freeaddrinfo(result);

        if (rp == NULL) {
            fprintf(stderr, "Can't bind to %s: %s\n", addr, strerror(err));
            return -1;
        }

    }

    return sock;
}

void
dyn_buf_init(dyn_buf *b, unsigned capacity)
{
    b->size = 0;
    b->capacity = capacity;
    b->data = malloc(capacity);
}

static void
dyn_buf_grow(dyn_buf *b, unsigned len)
{
    unsigned c = b->capacity + (b->capacity > 1 ? b->capacity >> 1 : 1);
    while (b->size + len > c)
        c += c >> 1;
    b->data = realloc(b->data, c);
    b->capacity = c;
}

void
dyn_buf_append(dyn_buf *b, const void *data, unsigned len)
{
    if (b->size + len > b->capacity)
        dyn_buf_grow(b, len);
    memcpy(b->data + b->size, data, len);
    b->size += len;
}

int
dyn_buf_read(dyn_buf *b, int fd, unsigned len)
{
    int nbytes;

    if (b->size + len > b->capacity)
        dyn_buf_grow(b, len);
    
    do {
        nbytes = recv(fd, b->data + b->size, len, MSG_NOSIGNAL);
    } while (nbytes == -1 && errno == EINTR);

    if (nbytes > 0)
        b->size += nbytes;

    return nbytes;
}

static void
tcp_cork(int fd, int cork)
{
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
}

bool
sock_send_buf(const void *buf, unsigned len, int fd, bool cork)
{
    unsigned nsend = 0;

    if (cork)
        tcp_cork(fd, 1);

    do {
        int nbytes;
        do {
            nbytes = send(fd, (char*)buf + nsend, len - nsend, MSG_NOSIGNAL);
        } while (nbytes == -1 && errno == EINTR);
        if (nbytes == -1) {
            if (cork) {
                int err = errno;
                tcp_cork(fd, 0);
                errno = err;
            }
            return false;
        }
        nsend += nbytes;
    } while (nsend < len);
    if (cork)
        tcp_cork(fd, 0);
    return true;
}

bool
sock_send_str(const char *str, int fd, bool cork)
{
    return sock_send_buf(str, strlen(str), fd, cork);
}

bool
send_100_continue(int fd)
{
    return sock_send_str("HTTP/1.1 100 Continue\r\n\r\n", fd, false);
}

void
chain_init(struct chain *ch)
{
    STAILQ_INIT(&ch->data);
    ch->c_off = 0;
}

/* Returns number of bytes sent.
 */
ssize_t
chain_send(struct chain *ch, int fd)
{
    size_t total = 0;
    struct msghdr mh;

    memset(&mh, 0, sizeof(mh));

    while (!STAILQ_EMPTY(&ch->data)) {
        unsigned i = 0;
        struct iovec v[32];
        struct chunk *c;
        unsigned off = ch->c_off;

        /* Prepare io vector */
        STAILQ_FOREACH(c, &ch->data, link) {
            v[i].iov_base = c->data + off;
            v[i++].iov_len = c->len - off;
            off = 0;
            if (i >= sizeof(v) / sizeof(*v))
                break;
        }

        /* Send it */
        ssize_t bytes;
        mh.msg_iov = v;
        mh.msg_iovlen = i;
        do {
            bytes = sendmsg(fd, &mh, MSG_NOSIGNAL);
        } while (bytes == -1 && errno == EINTR);

        if (bytes >= 0) {           /* >= to handle "strange" zero-length items */
            total += bytes;
            /* Remove completely sent chunks */
            for (i = 0; i < mh.msg_iovlen && bytes >= v[i].iov_len; i++) {
                struct chunk *c = STAILQ_FIRST(&ch->data);
                STAILQ_REMOVE_HEAD(&ch->data, link);
                free(c);
                bytes -= v[i].iov_len;
            }
            /* Handle corner case: if incomplete first piece had been incompletely sent few times in a row */
            ch->c_off = i ? bytes : ch->c_off + bytes;
        } else if (bytes == -1) {
            return errno == EAGAIN ? total : -1;
        }

    }

    return total;
}

/* Release memory allocated by chain data */
void
chain_cleanup(struct chain *ch)
{
    struct chunk *c, *tmp;
    STAILQ_FOREACH_SAFE(c, &ch->data, link, tmp) {
        free(c);
    }
    STAILQ_INIT(&ch->data);
    ch->c_off = 0;
}

#define CHUNK_SZ    64

void
chain_append(struct chain *ch, const void *data, unsigned len)
{
    struct chunk *c = STAILQ_LAST(&ch->data, chunk, link);
    /* "Partial fill" */
    if (c != NULL && c->len < c->capacity) {
        unsigned l = MIN(len, c->capacity - c->len);
        memcpy(c->data + c->len, data, l);
        c->len += l;
        len -= l;
        data = (const char*)data + l;
    }

    if (len == 0)
        return;

    if (len > CHUNK_SZ - sizeof(struct chunk)) {
        /* allocate "big" records in a single chunk */
        unsigned cap = (sizeof(*c) + len + CHUNK_SZ - 1) / CHUNK_SZ * CHUNK_SZ;
        c = malloc(cap);
        c->capacity = cap - sizeof(*c);
    } else {
        /* "small chunk" */
        unsigned cap = CHUNK_SZ;
        c = malloc(cap);
        c->capacity = cap - sizeof(*c);
    }
    c->len = len;
    memcpy(c->data, data, len);
    STAILQ_INSERT_TAIL(&ch->data, c, link);
}

uint64_t
chain_len(struct chain *ch)
{
    struct chunk *c;
    uint64_t len = 0;

    STAILQ_FOREACH(c, &ch->data, link)
        len += c->len;

    return len;
}

struct chunk*
chunk_new(unsigned sz)
{
    struct chunk *c = malloc(sizeof(*c) + sz);
    c->capacity = sz;
    c->len = sz;
    return c;
}
