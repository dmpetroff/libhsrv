#pragma once
#include <ev.h>
#include <stdbool.h>
#include <stdarg.h>
#include "pstr.h"

typedef struct http_server http_server;

#include "header.h"

/* HTTP headers. NOT NUL-terminated! */
struct http_ihdr {
    pstr_t      name;
    pstr_t      value;
};

typedef struct http_request {
    pstr_t              raw_header;     /* raw request header as read from socket */
    pstr_t              body;           /* raw request body as read from socket */
    pstr_t              method;         /* request method */
    pstr_t              path;           /* path (including query_string) */
    pstr_t              rqid;           /* unique request identifier suitable for logging.
                                         * guaranteed to be NUL-terminated and nonempty.
                                         * You can use it for logging in your application */
    /* indecies of last occurence of "well-known" headers.
     * Use HTTP_HDR(HHDR_xx, http_request*) macro to get actual
     * header value. */
    struct http_known_hdr hh;           /* "well-known" headers */
    struct http_ihdr    hdr[60];        /* raw input headers array (as they are parsed from request) */
    unsigned            nhdr;           /* number of headers */
    int                 version;        /* version: 0 or 1 for HTTP/1.0 and HTTP/1.1 */
} http_request;

typedef struct http_response http_response;
typedef void (*http_server_request_cb)(void *ctx, http_request *rq);

#define HTTP_INIT_DEFAULT   0
#define HTTP_INIT_NOAPR     1   /* disable apr pools initialization */
#define HTTP_INIT_NOSRAND   2   /* disable setting random seed */

#ifdef __cplusplus
extern "C" {
#endif /* C++ */

/* Invoke this function first. It will take care of apr initialization
 * and also will block SIGPIPE. The latter may be */
void http_server_initialize(int flags);

/* create new http server instance */
http_server* http_server_new();
/* add listen address to http server. Format: host:port */
bool http_server_bind(http_server *hs, const char *addr);
/* Setup custom "on-request" callback. This will prevent http_server_get_request from functioning correctly. */
void http_server_on_request(http_server *hs, http_server_request_cb cb, void *ctx);
/* start all necessary event handlers */
bool http_server_start(http_server *hs, struct ev_loop *loop);

/* Reason is copied. You can pass NULL in reason => it will be filled automatically */
void http_response_set_status(http_response *rs, int status, const char *reason);
/* Both header name and value are copied. Duplicate headers (like Set-Cookie) can be added this way */
void http_response_add_header(http_response *rs, const char *name, const char *val);
/* Upsert header. Both name and value are copied. Using case-insensitive compare!
 * @retval true => header had been replaced
 * @retval false => header had been added */
bool http_response_set_header(http_response *rs, const char *name, const char *val);
/* Appending to response body */
void http_response_body_append(http_response *rs, const void *data, unsigned len);
void http_response_body_printf(http_response *rs, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void http_response_body_vprintf(http_response *rs, const char *fmt, va_list ap);
/* Clear output headers, status and body. Usually needed if error occured */
void http_response_reset(http_response *rs);
/* Enqueue response for sending */
void http_response_submit(http_response *rs);

/* Wait for request to be read */
http_request* http_server_get_request(http_server *srv);
/* Return response object for specified request */
http_response* http_server_begin_response(http_request *rq);

#ifdef __cplusplus
}
#endif /* C++ */
