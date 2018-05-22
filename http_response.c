#include "http_server.h"
#include "internals.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>

void
http_response_init(http_response *rs)
{
    TAILQ_INIT(&rs->ohdr);
    chain_init(&rs->out);
    rs->status = NULL;
    rs->fout = NULL;
}

void
http_response_cleanup(http_response *rs)
{
    if (rs->fout)
        fclose(rs->fout);
    chain_cleanup(&rs->out);
    free(rs->status);
}

void
http_response_set_status(http_response *rs, int status, const char *reason)
{
    char buf[1024];
    unsigned len;
    if (reason) {
        len = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\n", status, reason);
    } else {
        len = snprintf(buf, sizeof(buf), "HTTP/1.1 %d HTTP_%d\r\n", status, status);
    }
    if (len >= sizeof(buf)) {
        len = sizeof(buf) - 1;
        memcpy(buf + len - 3, "\r\n", 2);
    }
    rs->status = realloc(rs->status, len + 1);
    memcpy(rs->status, buf, len + 1);
}

void
http_response_add_header(http_response *rs, const char *name, const char *val)
{
    struct http_exchange *ex = EX_FROM_RS(rs);
    struct http_ohdr *h = http_ohdr_new(ex->pool, name, val);
    TAILQ_INSERT_TAIL(&rs->ohdr, h, link);
}

bool
http_response_set_header(http_response *rs, const char *name, const char *val)
{
    /* TODO: avoid memory allocation when it can be done in-place? */
    struct http_exchange *ex = EX_FROM_RS(rs);
    struct http_ohdr *h = http_ohdr_new(ex->pool, name, val), *hh;
    /* Try to find header with such name */
    TAILQ_FOREACH(hh, &rs->ohdr, link) {
        if (hh->name.len == h->name.len && strncasecmp(hh->name.data, name, hh->name.len) == 0) {
            TAILQ_INSERT_BEFORE(hh, h, link);
            TAILQ_REMOVE(&rs->ohdr, hh, link);  /* apr_pool will manage memory */
            return true;
        }
    }
    TAILQ_INSERT_TAIL(&rs->ohdr, h, link);
    return false;
}

void
http_response_append(http_response *rs, const void *data, unsigned len)
{
    chain_append(&rs->out, data, len);
}

static ssize_t
rs_write(void *arg, const char *buf, size_t size)
{
    http_response *rs = arg;
    chain_append(&rs->out, buf, size);
    return size;
}

static FILE*
http_response_get_stdio_stream(http_response *rs)
{
    if (rs->fout == NULL) {
        static cookie_io_functions_t rs_ops = {
            NULL,
            rs_write,
            NULL,
            NULL
        };
        rs->fout = fopencookie(rs, "w", rs_ops);
    }
    return rs->fout;
}

void
http_response_body_append(http_response *rs, const void *data, unsigned len)
{
    if (rs->fout)
        /* Flush stream to avoid buffering problems */
        fflush(rs->fout);

    chain_append(&rs->out, data, len);
}

void
http_response_body_printf(http_response *rs, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(http_response_get_stdio_stream(rs), fmt, ap);
    va_end(ap);
}

void
http_response_body_vprintf(http_response *rs, const char *fmt, va_list ap)
{
    vfprintf(http_response_get_stdio_stream(rs), fmt, ap);
}

void
http_response_reset(http_response *rs)
{
    if (rs->fout) {
        fclose(rs->fout);
        rs->fout = NULL;
    }
    chain_cleanup(&rs->out);
    /* Reset output headers and status */
    TAILQ_INIT(&rs->ohdr);  /* yay, apr_pool will take care of memory! */
    free(rs->status);
    rs->status = NULL;
    /* Also clear memory pool */
    apr_pool_clear(EX_FROM_RS(rs)->pool);
}

void
http_response_submit(http_response *rs)
{
    struct http_exchange *ex = EX_FROM_RS(rs);
    pstr_t *rqid = &ex->rq.rqid;

    /* Flush output stream (if any) */
    if (rs->fout) {
        fflush(rs->fout);
        fclose(rs->fout);
        rs->fout = NULL;
    }

    char buf[128];
    unsigned bl = sprintf(buf, "Content-Length: %" PRIu64 "\r\nX-Trace: ", chain_len(&rs->out));

    /* build headers */
    unsigned sl = strlen(rs->status);
    unsigned hdr_sz = strlen(rs->status) + bl + rqid->len + 2 + /*\r\n*/2;
    struct http_ohdr *h;
    TAILQ_FOREACH(h, &rs->ohdr, link) {
        hdr_sz += 4 + h->name.len + h->value.len;
    }
    struct chunk *hh = chunk_new(hdr_sz);
    char *o = hh->data;

    /* Copy status line */
    memcpy(o, rs->status, sl); o += sl;

    /* Copy headers */
    TAILQ_FOREACH(h, &rs->ohdr, link) {
        unsigned l = h->name.len + h->value.len + 4;
        memcpy(o, h->name.data, l);
        o += l;
    }

    /* Append content-length */
    memcpy(o, buf, bl); o += bl;
    memcpy(o, rqid->data, rqid->len); o += rqid->len;
    o[0] = '\r'; o[1] = '\n';
    o[2] = '\r'; o[3] = '\n';
    o += 4;
    STAILQ_INSERT_HEAD(&rs->out.data, hh, link);

    /* Mark response as "ready" */
    ex->state = HEST_SUBMITTED;     /* don't need atomicity here */
    ev_async_send(ex->loop, &ex->ntfy);
}
