#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include "picohttpparser.h"
#include <netdb.h>
#include <errno.h>
#include "queue.h"
#include <ev.h>
#include <stdbool.h>
#include "http_server.h"

#include "internals.h"

static http_server *srv;

static void
handle_request(http_request *rq, const char *self, int rn)
{
        unsigned i;
        char *nr = (char*)"--";
        for (i = 0; i < rq->nhdr; i++) {
            pstr_t *n = &rq->hdr[i].name;
            if (n->len == 2 && memcmp(n->data, "nn", 2) == 0) {
                nr = rq->hdr[i].value.data;
                nr[rq->hdr[i].value.len] = 0;
                break;
            }

        }
        printf("got request %p # %s (%d)\n", rq, nr, rn);
        http_response *rs = http_server_begin_response(rq);
        //printf("GOT REQUEST: %p\n", rq);
        http_response_set_status(rs, 200, "OK");
        http_response_add_header(rs, "X-thread-id", self);
        http_response_add_header(rs, "Connection", "keep-alive");
        http_response_body_printf(rs, "[%s] In response to %.*s: it's alive! Request body was %u bytes long\n",
                                  self, rq->path.len, rq->path.data, rq->body.len);
#define SHOW_HDR(name) \
        if (rq->hh.name) \
            http_response_body_printf(rs, "%s => %.*s\n", #name, rq->hh.name->len, rq->hh.name->data); \
        else \
            http_response_body_printf(rs, "%s => <nil>\n", #name)
        SHOW_HDR(host);
        SHOW_HDR(user_agent);
        http_response_body_printf(rs, "request-id => <%s>\n", rq->rqid.data);
        /* sleep befor posting result */
        //sleep(1);
        http_response_submit(rs);
}

void*
thr_exec(void *arg)
{
    char self[32];
    snprintf(self, sizeof(self), "%d", (int)(intptr_t)arg);
    int rn = 0;

    for (;;) {
        handle_request(http_server_get_request(srv), self, rn++);
    }

    return NULL;
}

static void
cb_exec(void *ctx, http_request *rq)
{
    static int nr = 0;
    handle_request(rq, "<SYNC>", nr++);
}

int main(int argc, char **argv)
{
#if 1
    pthread_t thr;
    struct ev_loop *loop;

    http_server_initialize(HTTP_INIT_DEFAULT);
    srv = http_server_new();

    if (argc > 1 && strcmp(argv[1], "--sync") == 0) {
        http_server_on_request(srv, cb_exec, NULL);
    } else {
        for (unsigned i = 0; i < 5; i++)
            pthread_create(&thr, NULL, thr_exec, (void*)(intptr_t)i);
    }

    pthread_setname_np(pthread_self(), "HTTP/net");
    loop = EV_DEFAULT;

    http_server_bind(srv, "4567");
    http_server_start(srv, loop);

    printf("RUNNING\n");
    ev_run(loop, 0);
    printf("ev_run exited\n");
    getchar();
#else
    apr_pool_initialize();

    struct http_exchange *srq = http_exchange_new();
    http_response *rs = &srq->rs;
    http_response_set_status(rs, 200, "OK");
    for (int i = 0; i < 5; i++) {
        http_response_body_printf(rs, "%02d Hello world\n", i);
    }
    http_response_submit(rs);
    chain_send(&rs->out, 1);

    http_exchange_free(srq);
#endif
    return 0;
}
