#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>

int load_curl()
{
    CURL *c;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_URL, "http://localhost:4567/dummy");
    for (;;) {
        if (curl_easy_perform(c) != CURLE_OK)
            break;
    }
    return 0;
}

int load_sock()
{
    int i = 1;
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4567);
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("connect");
        return 3;
    }
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i));
    for (i = 0; i < 20; i++) {
        char rq[1024];
        unsigned len = sprintf(rq, "GET /dummy HTTP/1.1\r\nnn: %02d\r\n\r\n", i);
        if (write(sock, rq, len) != len) {
            fprintf(stderr, "write failed\n");
            return 1;
        }
        usleep(25000);
        printf("send %2d domplete\n", i);
    }

    for (i = 0; i < 5; i++) {
        char buf[4096];
        int len;
        if ((len = read(sock, buf, sizeof(buf))) <= 0) {
            fprintf(stderr, "read failed\n");
            return 2;
        }
        //printf("recv %2d complete\n", i);
        write(1, buf, len);
    }
    printf("closing socket\n");
    close(i);
    return 0;
}

int main()
{
    return load_sock();
}
