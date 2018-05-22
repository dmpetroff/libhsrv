#include "internals.h"
#include <stdlib.h>

struct http_ohdr*
http_ohdr_new(apr_pool_t *pool, const char *name, const char *value)
{
    char *c;
    struct http_ohdr *h;
    unsigned nl = strlen(name), vl = strlen(value);

    h = apr_palloc(pool, sizeof(*h) + nl + /*": "*/2 + vl + /*\r\n*/2);
    c = (char*)(h + 1);

    /* copy name */
    h->name.data = c;
    h->name.len = nl;
    memcpy(c, name, nl);
    c += nl;

    *c++ = ':'; *c++ = 0x20;

    /* copy value */
    h->value.data = c;
    h->value.len = vl;
    memcpy(c, value, vl);

    c[vl] = '\r'; c[vl + 1] = '\n';
    return h;
}

struct http_exchange *
http_exchange_new()
{
    struct http_exchange *ex = malloc(sizeof(*ex));
    http_response_init(&ex->rs);
    http_request_init(&ex->rq);
    ex->state = HEST_RECV;
    apr_pool_create_unmanaged(&ex->pool);
    dyn_buf_init(&ex->rqbuf, 2048);
    return ex;
}

void
http_request_init(http_request *rq)
{
    rq->raw_header.data = NULL;     /* only this is required */
    rq->rqid.data = NULL;
    rq->rqid.len = 0;
}

void
http_request_cleanup(http_request *rq)
{
    /* Request data belongs to pool and released automatically */
}

void
http_exchange_free(struct http_exchange *ex)
{
    http_request_cleanup(&ex->rq);
    http_response_cleanup(&ex->rs);
    free(ex->rqbuf.data);
    apr_pool_destroy(ex->pool);
    free(ex);
}

/* Generate "random" base58 digits. Resulting string will not be NUL-terminated. */
static void
gen_rndid(char *buf, unsigned ndigits)
{
    unsigned i;
    for (i = 0; i < ndigits; i++) {
        long rnd = random();
        unsigned long rmax;
        /* base is taken from https://en.wikipedia.org/wiki/Base58 (short url for Flickr) */
        static const char base[] = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
#define BASE_LEN ((unsigned)(sizeof(base) / sizeof(*base) - 1))
        for (rmax = RAND_MAX; i < ndigits && rmax >= BASE_LEN; rmax /= BASE_LEN, i++) {
            buf[i] = base[rnd % BASE_LEN];
            rnd /= BASE_LEN;
        }
    }
#undef BASE_LEN
}

/* Use client-supplied or generate unique request id */
void
assign_request_id(http_request *rq, apr_pool_t *pool)
{
    pstr_t id;
    unsigned rl;

    if (rq->rqid.len) {
        /* Concatenate with '%' symbol */
        rl = 3;
        id.len = rq->rqid.len + 1 + rl;
        id.data = apr_palloc(pool, id.len + 1);
        memcpy(id.data, rq->rqid.data, rq->rqid.len);
        id.data[rq->rqid.len] = '%';
    } else {
        rl = 5;
        id.len = rl;
        id.data = apr_palloc(pool, id.len + 1);
    }
    gen_rndid(id.data + (id.len - rl), rl);
    id.data[id.len] = 0;

    rq->rqid = id;
}
