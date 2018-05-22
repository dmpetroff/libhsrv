#include "http_server.h"
#include "internals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <apr_pools.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <ev.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/uio.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include "picohttpparser.h"

#if 0
#   define ELOG(msg, ...) fprintf(stderr, "%s:%u: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#   define ELOG(msg, ...)
#endif

/* Start new connection handling */
static void http_conn_start(EV_P_ http_server *hs, int fd);
void http_conn_abort(EV_P_ struct http_conn *hc);
/* Invoke this to gracefully shutdown connection: stop read io watcher,
 * wait for completion of all envelopes */
void http_conn_shutdown(EV_P_ struct http_conn *hc);

/* Receive request header callback. */
static void cb_http_conn_recv_hdr(EV_P_ ev_io *w, int revents);
/* Receive request body callback. */
static void cb_http_conn_recv_body(EV_P_ ev_io *w, int revents);
static void http_conn_free(struct http_conn *hc);

/***************************************************************************************/
/*                                    Callback hell                                    */
/***************************************************************************************/
static void
cb_http_accept(EV_P_ ev_io *w, int revents)
{
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } addr;
    socklen_t sl = sizeof(addr);
    int fd;

retry:
    fd = accept4(w->fd, &addr.sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (fd == -1) {
        switch (errno) {
        case EAGAIN:
            return;
        case EINTR:
            goto retry;
        default:
            ELOG("accept: %s", strerror(errno));
            return;
        }
    }

    /* For inet namespace set linger option */
    switch (addr.sa.sa_family) {
    case AF_INET:
    case AF_INET6: {
        struct linger l = {1, 1};
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        }
        break;
    }

    http_conn_start(EV_A_ w->data, fd);
}

static void
cb_http_conn_send(EV_P_ ev_io *w, int revents)
{
    struct http_conn *hc = STRUCT_FROM_FIELD(w, struct http_conn, snd);
    if (revents & EV_WRITE) {
        http_response *rs;
        struct http_exchange *ex;

        ex = STAILQ_FIRST(&hc->sndq);
        if (ex == NULL || ex->state < HEST_SEND) {
            /* if there's nothing to sent of request is not ready, stop write watcher */
            ELOG("Response completely sent");
            ev_io_stop(EV_A_ w);
            return;
        }
        /* update state. This is mostly informational action and no atomicity is required */

        rs = &ex->rs;

        if (chain_send(&rs->out, w->fd) == -1) {
            /* Abort connection on send errors */
            ELOG("Error while sending request: %s", strerror(errno));
            http_conn_abort(EV_A_ hc);
            return;
        }

        if (STAILQ_EMPTY(&rs->out.data)) {
            ELOG("chain fully send, releasing");
            /* pick next item */
            STAILQ_REMOVE_HEAD(&hc->sndq, link);
            LIST_REMOVE(ex, clist);
            http_exchange_free(ex);

            /* If send queue is empty, stop event watcher */
            if (STAILQ_EMPTY(&hc->sndq)) {
                ev_io_stop(EV_A_ w);
                /* shutdown if there will be no more requests */
                if (hc->state >= HCST_CLIENT_EOF) {
                    http_conn_shutdown(EV_A_ hc);
                    return;
                }
            }
        }
    }
}

/* This method should initiate response sending */
static void
cb_http_conn_reply_ntfy(EV_P_ ev_async *w, int revents)
{
    struct http_exchange *ex = STRUCT_FROM_FIELD(w, struct http_exchange, ntfy);
    struct http_conn *hc = w->data;

    ev_async_stop(EV_A_ w);
    /* Mark request as "ready" */
    ex->state = HEST_SEND;
    if (hc->state == HCST_ABORTED) {
        /* sndq is empty at this point (see http_conn_abort) */
        LIST_REMOVE(ex, clist);
        http_exchange_free(ex);
        if (LIST_EMPTY(&hc->exs))
            http_conn_free(hc);
    } else if (ex == STAILQ_FIRST(&hc->sndq)) {
        /* schedule sending HTTP response */
        ev_io_start(EV_A_ &hc->snd);
    }
}

static void
http_conn_free(struct http_conn *hc)
{
    if (hc->rq)
        http_exchange_free(hc->rq);

    if (LIST_EMPTY(&hc->exs))
        free(hc);
}

/* Enqueue request asynchronously */
static void
http_server_enqueue_request_async(void *ctx, http_request *rq)
{
    http_server *srv = ctx;
    struct http_exchange *ex = EX_FROM_RQ(rq);

    pthread_mutex_lock(&srv->rq_lock);
    TAILQ_INSERT_TAIL(&srv->rqueue, ex, slink);
    pthread_mutex_unlock(&srv->rq_lock);
    pthread_cond_signal(&srv->rq_ntfy);
}

void
http_conn_abort(EV_P_ struct http_conn *hc)
{
    hc->state = HCST_ABORTED;

    /* Immediately release active http_exchange. */
    if (hc->rq) {
        http_exchange_free(hc->rq);
        hc->rq = NULL;
    }
    ev_io_stop(EV_A_ &hc->rcv);
    ev_io_stop(EV_A_ &hc->snd);
    //shutdown(hc->rcv.fd, SHUT_RDWR);
    close(hc->rcv.fd);  /* immediate close without shutdown */

    /* empty send queue (because we no longer need it) */
    STAILQ_INIT(&hc->sndq);

    /* Now we need to remove all enqueued requests from server */
    if (!LIST_EMPTY(&hc->exs)) {
        http_server *srv = hc->srv;
        struct http_exchange *ex, *tmp;
        LIST_HEAD(,http_exchange) freeme;   /* do not perform free under locks! */
        LIST_INIT(&freeme);

        pthread_mutex_lock(&srv->rq_lock);
        LIST_FOREACH_SAFE(ex, &hc->exs, clist, tmp) {
            /* all watchers are stopped now, it's safe to
             * kill everything with fire^W free */
            switch (ex->state) {
            case HEST_RECV:         /* what? should never happen */
                assert("fix your logic");
                break;
            case HEST_ENQUEUED:     /* enqueued items additionally need to be removed from server queue */
                if (srv->on_request == http_server_enqueue_request_async)   /* TODO: this is a dirty hack */
                    TAILQ_REMOVE(&srv->rqueue, ex, slink);
                /* fallthru */
            case HEST_SUBMITTED:    /* it's safe to destroy submitted entries because they are belong
                                     * to our thread */
            case HEST_SEND:         /* usually HEST_SEND is the item that caused connection abort */
                /* remove it from queue (free later) */
                LIST_REMOVE(ex, clist);
                LIST_INSERT_HEAD(&freeme, ex, clist);
                break;
            case HEST_PROCESSING:   /* can't do anything - it's claimed by worker thread */
                break;
            }
        }
        pthread_mutex_unlock(&srv->rq_lock);

        /* now we can deal with items we no longer need */
        LIST_FOREACH_SAFE(ex, &freeme, clist, tmp) {
            if (ex->state == HEST_SUBMITTED || ex->state == HEST_ENQUEUED) {
                /* ev_async watcher is still active - deal with it */
                ev_async_stop(EV_A_ &ex->ntfy);
            }
            http_exchange_free(ex);
        }
    }

    http_conn_free(hc);
}

void
http_conn_shutdown(EV_P_ struct http_conn *hc)
{
    /* we're in header recv state and suddenly got EOF. That means hc->rq is incomplete and never
     * will be complete => discard it */
    if (hc->rq) {
        http_exchange_free(hc->rq);
        hc->rq = NULL;
    }
    /* Stop read watcher, but don't destroy connection object if it has nonempty queue */
    ev_io_stop(EV_A_ &hc->rcv);
    if (LIST_EMPTY(&hc->exs)) {
        int fd = hc->rcv.fd;
        shutdown(fd, SHUT_RDWR);
        http_conn_free(hc);
        close(fd);
        return;
    }
}

/* Enqueue active request from hc for processing */
void
http_enqueue_request(EV_P_ http_server *srv, struct http_conn *hc)
{
    /* no state checking here because request enqueue can be only invoked
     * byt cb_http_conn_recv_* handlers which are stopped on abort */
    struct http_exchange *ex = hc->rq;
    hc->rq = NULL;

    assign_request_id(&ex->rq, ex->pool);
    ev_async_init(&ex->ntfy, cb_http_conn_reply_ntfy);
    ex->ntfy.data = hc;
    ex->state = HEST_ENQUEUED;
    ev_async_start(EV_A_ &ex->ntfy);

    /* You may think that this is redundant, but we NEED to keep queue
     * of all requests in order we've received them to keep correct
     * response order.
     * So it's mandatory to enqueue exchange right after request had been received
     * rather that when response is ready */
    STAILQ_INSERT_TAIL(&hc->sndq, ex, link);
    /* Also this is right place to place out request in global queue */
    LIST_INSERT_HEAD(&hc->exs, ex, clist);

    srv->on_request(srv->on_request_ctx, &ex->rq);
    ELOG("submitted!");
}

#include "header.gperf.c"

/* @param rq request to initialize
 * @param b dynamic buffer where request header and partially read body are located
 * @param hdr_len length of the header in b
 * @param method http request method
 * @param path request uri (including query string)
 * @param version 1/0 - HTTP version minor
 * @param hdr headers array
 * @param nhdr number of request headers
 * @retval 0 => request is fully read and can be processed
 * @retval -1 => malformed request
 * @retval -2 => request body still needs to be read
 * @retval -3 => got "expect: 100-continue"
 * @retval -4 => request entity too large + keep-alive
 * @retval -5 => request entity too large + abort connection
 */
static int
init_request(http_request *rq, dyn_buf *b, unsigned hdr_len,
             phr_str *method, phr_str *path, int version,
             struct phr_header *hdr, unsigned nhdr, apr_pool_t *pool,
             uint64_t *remaining)
{
    int retval = 0;
    unsigned i;
    int prqid = -1;
    char *data;
    bool has_content_len = false;
    uint64_t content_len = 0;

    /* Clear "known headers" references */
    memset(&rq->hh, 0, sizeof(rq->hh));
    /* Find content-length header */
#define HCMP(h, s) ((h).name_len == sizeof(s) - 1 && strncasecmp((h).name, s, sizeof(s) - 1) == 0)
#define VCMP(h, s) ((h).value_len == sizeof(s) - 1 && strncasecmp((h).value, s, sizeof(s) - 1) == 0)
    for (i = 0; i < nhdr; i++) {
        const struct gp_http_hdr *hh = http_hdr_find(hdr[i].name, hdr[i].name_len);
        if (hh == NULL) /* ignore unknown headers */
            continue;
        /* Store reference */
        if (hh->kw_off)
            *(pstr_t**)((char*)rq + hh->kw_off) = &rq->hdr[i].value;

        if (hh->code == HHDR_CONTENT_LENGTH) {
            const char *p = hdr[i].value, *e = p + hdr[i].value_len;
            while (p < e && isspace(*p))
                p++;
            if (p == e || !isdigit(*p))
                return -1;
            while (p < e && isdigit(*p)) {
                content_len = content_len * 10 + (*p - '0');
                p++;
            }
            if (p != e || !isspace(*p))
                return -1;
            has_content_len = true;
        /* disallow chunked transfer-encoding */
        } else if (hh->code == HHDR_TRANSFER_ENCODING && VCMP(hdr[i], "chunked")) {
            return -1;  /* chunked is not supported */
        } else if (hh->code == HHDR_EXPECT && VCMP(hdr[i], "100-continue")) {
            retval = -3;
        } else if (hh->code == HHDR_X_REQ_ID) {
            prqid = i;
        }
    }

    /* Reject request with body larger that 2^32-1 */
    if (content_len + hdr_len > UINT32_MAX)
        return retval == -3 ? -4 : -5;

#define SCMP(s, v) ((s)->len == sizeof(v) - 1 && strncasecmp((s)->data, v, sizeof(v) - 1) == 0)
    if ((SCMP(method, "post") || SCMP(method, "put"))
            && !has_content_len)
        return -1;

    if (b->size > hdr_len + content_len) {
        /* Some extra data looks like http request pipelining which we don't support now */
        return -1;
    }
    /* Allocate header + body */
    data = apr_palloc(pool, hdr_len + content_len);
    memcpy(data, b->data, hdr_len);

    /* Translate all pointers */
    rq->method.data = data + (method->data - b->data);
    rq->method.len = method->len;
    rq->path.data = data + (path->data - b->data);
    rq->path.len = path->len;
    rq->version = version;
    rq->nhdr = nhdr;

    for (i = 0; i < nhdr; i++) {
        rq->hdr[i].name.data = data + (hdr[i].name - b->data);
        rq->hdr[i].name.len = hdr[i].name_len;
        rq->hdr[i].value.data = data + (hdr[i].value - b->data);
        rq->hdr[i].value.len = hdr[i].value_len;
    }

    /* Setup raw body/header */
    rq->raw_header.data = data;
    rq->raw_header.len = hdr_len;
    rq->body.data = data + hdr_len;
    rq->body.len = content_len;
    if (prqid != -1)            /* copy request id */
        rq->rqid = rq->hdr[prqid].value;

    if (retval == -3) {
        *remaining = content_len;
        return -3;
    } else if (b->size < hdr_len + content_len) {
        /* Request had been partially read */
        memcpy(data, b->data, b->size);
        *remaining = hdr_len + content_len - b->size;
        b->size = 0;
        return -2;
    } else {
        /* Request is fully buffered */
        memcpy(data, b->data, hdr_len + content_len);
        b->size = 0;
        return 0;
    }
}

static void
cb_http_conn_recv_body(EV_P_ ev_io *w, int revents)
{
    struct http_conn *hc = STRUCT_FROM_FIELD(w, struct http_conn, rcv);
    if (revents & EV_READ) {
        struct http_exchange *ex = hc->rq;
        http_request *rq = &ex->rq;
        ssize_t bytes;
        do {
            bytes = recv(w->fd, rq->body.data + rq->body.len - ex->remaining, ex->remaining, MSG_NOSIGNAL);
        } while (bytes == -1 && errno == EINTR);
        if (bytes > 0) {
            ELOG("[%p] got %zd bytes of %" PRIu64, hc, bytes, ex->remaining);
            ex->remaining -= bytes;
            if (ex->remaining == 0) {
                http_enqueue_request(EV_A_ hc->srv, hc);
                /* Prepare to read next request */
                ev_set_cb(&hc->rcv, cb_http_conn_recv_hdr);
            }
        } else if (bytes == 0) {
            /* (unexpected) EOF - we don't support http/1.0 semantic yet */
            http_conn_abort(EV_A_ hc);
            return;
        } else if (bytes == -1) {
            int err = errno;
            if (err == EAGAIN)
                return;
            ELOG("cb_http_read_body: %s", strerror(err));
            http_conn_abort(EV_A_ hc);
            return;
        }
    }
}

/* Receive header part */
static void
cb_http_conn_recv_hdr(EV_P_ ev_io *w, int revents)
{
    struct http_conn *hc = STRUCT_FROM_FIELD(w, struct http_conn, rcv);
    assert(hc->state != HCST_ABORTED);

    if (revents & EV_READ) {
        /* get active request */
        if (hc->rq == NULL) {
            /* TODO: avoid request allocation */
            hc->rq = http_exchange_new();
            hc->rq->loop = loop;
        }
        unsigned lastlen = hc->rq->rqbuf.size;

        int bytes = dyn_buf_read(&hc->rq->rqbuf, w->fd, 2048);
        if (bytes == 0) {
            /* EOF when we are not waiting for request completion is ok */
            if (!LIST_EMPTY(&hc->exs)) {
                printf("got EOF on active connection\n");
                http_conn_abort(EV_A_ hc);
                return;
            }
            hc->state = HCST_CLIENT_EOF;
            if (hc->rq->rqbuf.size == 0)
                http_conn_shutdown(EV_A_ hc);
            else
                http_conn_abort(EV_A_ hc);  /* EOF in the middle of header is BAD */
            return;
        }
        if (bytes == -1) {
            int err = errno;
            if (err == EAGAIN)
                return;
            ELOG("cb_http_conn_recv_hdr: %s", strerror(err));
            http_conn_shutdown(EV_A_ hc);
            return;
        }
        /* If */
        http_request *rq = &hc->rq->rq;
        int version;
        uint64_t left;
        phr_str method, path;
        struct phr_header hdr[sizeof(rq->hdr) / sizeof(*rq->hdr)];
        size_t nhdr = sizeof(hdr) / sizeof(*hdr);
        int result = phr_parse_request(hc->rq->rqbuf.data, hc->rq->rqbuf.size,
                                       &method.data, &method.len, &path.data, &path.len,
                                       &version, hdr, &nhdr, lastlen);
        switch (result) {
        case -1:
            /* malformed request */
            http_conn_shutdown(EV_A_ hc);
            ELOG("FAIL\n");
            break;
        case -2:
            /* need more data */
            return;
        default:
            /* need to read request body */
            switch (init_request(rq, &hc->rq->rqbuf, result, &method, &path, version, hdr, nhdr, hc->rq->pool, &left)) {
            case -1:
                ELOG("malformed request");
                http_conn_abort(EV_A_ hc);
                return;
            case -2:
                ELOG("[%p] need to read more body (%" PRIu64 " bytes more)", hc, left);
                hc->rq->remaining = left;
                ev_set_cb(w, cb_http_conn_recv_body);
                return;
            case -3:
                if (!send_100_continue(w->fd)) {
                    ELOG("failed to send http-100-continue");
                    http_conn_abort(EV_A_ hc);
                    return;
                }
                ELOG("going to fetch %u bytes (%u on wire)", rq->body.len, hc->rq->rqbuf.size);
                hc->rq->remaining = rq->body.len;
                ev_set_cb(w, cb_http_conn_recv_body);
                return;
            /* large body + expect-100-continue: we can respond with HTTP 413 and keep-alive */
            case -4:
                /* TODO: learn to keep-alive!
                 * but for now just report 413 and abort connection */
            /* large body on wire => 413 + close connection */
            case -5:
                ELOG("request entity too large, closing connection");
                sock_send_str("HTTP/1.1 413 Request Entity Too Large\r\n"
                              "Content-Length: 0\r\n"
                              "Connection: close\r\n\r\n",
                              w->fd, true);
                http_conn_abort(EV_A_ hc);
                return;
            case 0:
                ELOG("body fully read");
                http_enqueue_request(EV_A_ hc->srv, hc);
                return;
            default:
                ELOG("unexpected init_request result");
                abort();
            }
        }
    }
}

/* Start reading http requests from socket */
static void
http_conn_start(EV_P_ http_server *hs, int fd)
{
    struct http_conn *hc = malloc(sizeof(*hc));
    STAILQ_INIT(&hc->sndq);
    LIST_INIT(&hc->exs);
    hc->srv = hs;
    hc->rq = NULL;
    hc->state = HCST_ACTIVE;

    ev_io_init(&hc->rcv, cb_http_conn_recv_hdr, fd, EV_READ);
    ev_io_start(EV_A_ &hc->rcv);
    ev_io_init(&hc->snd, cb_http_conn_send, fd, EV_WRITE);
}

/* Create new instance of http server */
http_server*
http_server_new()
{
    http_server *hs = calloc(1, sizeof(http_server));
    LIST_INIT(&hs->srv_sock);
    TAILQ_INIT(&hs->rqueue);
    pthread_mutex_init(&hs->rq_lock, NULL);
    pthread_cond_init(&hs->rq_ntfy, NULL);

    /* setup "on-request" callback */
    hs->on_request = http_server_enqueue_request_async;
    hs->on_request_ctx = hs;
    return hs;
}

/* Override callback */
void
http_server_on_request(http_server *hs, http_server_request_cb cb, void *ctx)
{
    hs->on_request = cb;
    hs->on_request_ctx = ctx;
}

/* Listen on specified address */
bool
http_server_bind(http_server *hs, const char *addr)
{
    int fd, len;
    struct srv_socket *ss;
    
    fd = make_and_bind_socket(addr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd == -1)
        return false;

    len = strlen(addr) + 1;
    ss = malloc(sizeof(*ss) + len);

    ss->addr = (char*)(ss + 1);
    memcpy((char*)ss->addr, addr, len);
    ss->io.fd = fd;
    LIST_INSERT_HEAD(&hs->srv_sock, ss, link);

    return true;
}

/* Start HTTP server on default event loop */
bool
http_server_start(http_server *hs, struct ev_loop *loop)
{
    struct srv_socket *ss;

    /* Start listening */
    LIST_FOREACH(ss, &hs->srv_sock, link) {
        if (listen(ss->io.fd, 100) == -1) {
            fprintf(stderr, "Can't listen on [%s]: %s", ss->addr, strerror(errno));
            return false;
        }
        ev_io_init(&ss->io, cb_http_accept, ss->io.fd, EV_READ);
        ss->io.data = hs;
        ev_io_start(loop, &ss->io);
    }

    return true;
}

http_request*
http_server_get_request(http_server *srv)
{
    struct http_exchange *ex;

    pthread_mutex_lock(&srv->rq_lock);
    while (TAILQ_EMPTY(&srv->rqueue))
        pthread_cond_wait(&srv->rq_ntfy, &srv->rq_lock);
    ex = TAILQ_FIRST(&srv->rqueue);
    ex->state = HEST_PROCESSING;
    TAILQ_REMOVE(&srv->rqueue, ex, slink);
    pthread_mutex_unlock(&srv->rq_lock);

    return &ex->rq;
}

http_response*
http_server_begin_response(http_request *rq)
{
    return &EX_FROM_RQ(rq)->rs;
}

void
http_server_initialize(int flags)
{
    static bool initialized = false;
    if (initialized)
        return;
    initialized = true;

    if ((flags & HTTP_INIT_NOAPR) == 0)
        apr_pool_initialize();

    if ((flags & HTTP_INIT_NOSRAND) == 0) {
        int fd;
        unsigned int seed;
        /* try to use /dev/urandom for seed */
        fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1 || read(fd, &seed, sizeof(seed)) != sizeof(seed)) {
            /* fallback to current time + pid */
            seed = time(NULL) ^ getpid();
        }
        if (fd != -1)
            close(fd);

        srand(seed);
        /* see http://stackoverflow.com/questions/7866754/why-does-rand-7-always-return-0 */
        rand();
    }
}
