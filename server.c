/*
 * Log Analyzer web backend.
 *
 *   Browser  <-->  this server (sockets)  -->  analyze() from analyzer_core.h
 *
 * Routes:
 *   GET  /               -> public/index.html
 *   GET  /api/health     -> {"status":"ok"}
 *   POST /api/analyze    -> body = raw log text, reply = JSON statistics
 *
 * Builds on Linux/macOS (pthreads) and Windows (Winsock, MinGW or MSVC).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyzer_core.h"

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef SOCKET sock_t;
  #define BAD_SOCK      INVALID_SOCKET
  #define CLOSE_SOCK    closesocket
  #define SEND_FLAGS    0
  #define THREAD_RET    DWORD WINAPI
  typedef LPVOID        thread_arg;
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <signal.h>
  #include <errno.h>
  typedef int sock_t;
  #define BAD_SOCK      (-1)
  #define CLOSE_SOCK    close
  #ifdef MSG_NOSIGNAL
    #define SEND_FLAGS  MSG_NOSIGNAL
  #else
    #define SEND_FLAGS  0
  #endif
  #define THREAD_RET    void *
  typedef void *        thread_arg;
#endif

#define DEFAULT_PORT 8080
#define HDR_MAX      16384
#define TOP_N        10

/* ---------------------------------------------------------------- responses */
static void send_all(sock_t fd, const char *buf, size_t len)
{
    while (len > 0) {
        int n = (int)send(fd, buf, (int)(len > 65536 ? 65536 : len), SEND_FLAGS);
        if (n <= 0) return;
        buf += n;
        len -= (size_t)n;
    }
}

static void respond(sock_t fd, int code, const char *reason, const char *ctype,
                    const char *body, size_t len)
{
    char head[256];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n"
                     "X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n"
                     "Connection: close\r\n\r\n",
                     code, reason, ctype, (unsigned long)len);
    send_all(fd, head, (size_t)n);
    send_all(fd, body, len);
}

static void respond_json(sock_t fd, int code, const char *reason, const char *json)
{
    respond(fd, code, reason, "application/json; charset=utf-8", json, strlen(json));
}

static void respond_error(sock_t fd, int code, const char *reason, const char *msg)
{
    char body[256];
    snprintf(body, sizeof body, "{\"error\":\"%s\"}", msg);
    respond_json(fd, code, reason, body);
}

static void serve_index(sock_t fd)
{
    FILE *f = fopen("public/index.html", "rb");
    char *data;
    long sz;

    if (!f) { respond_error(fd, 404, "Not Found", "public/index.html missing - run the server from the project folder"); return; }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    rewind(f);
    data = (char *)malloc((size_t)sz + 1);
    if (!data || fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(data);
        respond_error(fd, 500, "Internal Server Error", "read failed");
        return;
    }
    fclose(f);
    respond(fd, 200, "OK", "text/html; charset=utf-8", data, (size_t)sz);
    free(data);
}

/* ------------------------------------------------------------ /api/analyze */
static void handle_analyze(sock_t fd, const char *text)
{
    Stats s;
    char out[2048];
    size_t n = 0;
    int shown = 0, i;
    int used[128] = {0};

    analyze(text, &s);

    n += (size_t)snprintf(out + n, sizeof out - n,
        "{\"total\":%lu,\"alphabets\":%lu,\"digits\":%lu,\"specials\":%lu,"
        "\"whitespace\":%lu,\"top\":[",
        s.total, s.alphabets, s.digits, s.specials, s.whitespace);

    /* Top N printable characters (33..126), highest count first */
    while (shown < TOP_N) {
        int best = -1;
        for (i = 33; i < 127; i++)
            if (!used[i] && s.freq[i] > 0 && (best < 0 || s.freq[i] > s.freq[best]))
                best = i;
        if (best < 0) break;
        used[best] = 1;

        n += (size_t)snprintf(out + n, sizeof out - n, "%s{\"char\":\"%s%c\",\"count\":%lu}",
                              shown ? "," : "",
                              (best == '"' || best == '\\') ? "\\" : "",
                              best, s.freq[best]);
        shown++;
    }
    snprintf(out + n, sizeof out - n, "]}");
    respond_json(fd, 200, "OK", out);
}

/* ---------------------------------------------------------- request parsing */
/* Case-insensitive search for "Content-Length:" in the header block. Returns -1 if absent. */
static long find_content_length(const char *hdr, size_t hdr_len)
{
    static const char key[] = "content-length:";
    size_t i, k, klen = sizeof key - 1;

    for (i = 0; i + klen < hdr_len; i++) {
        if (i > 0 && hdr[i - 1] != '\n') continue;          /* only at line starts */
        for (k = 0; k < klen; k++) {
            char c = hdr[i + k];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            if (c != key[k]) break;
        }
        if (k == klen) return atol(hdr + i + klen);
    }
    return -1;
}

static void handle_connection(sock_t fd)
{
    char *req = (char *)malloc(HDR_MAX + MAX_INPUT + 1);
    size_t got = 0, hdr_end = 0, need = 0;
    char method[8], target[2048], *q, *body;
    long clen = 0;

    if (!req) { respond_error(fd, 500, "Internal Server Error", "out of memory"); return; }

    for (;;) {
        size_t cap = hdr_end ? need : HDR_MAX;
        int r;
        if (got >= cap) break;
        r = (int)recv(fd, req + got, (int)(cap - got), 0);
        if (r <= 0) break;
        got += (size_t)r;
        req[got] = '\0';

        if (!hdr_end) {
            char *p = strstr(req, "\r\n\r\n");
            if (!p) continue;
            hdr_end = (size_t)(p - req) + 4;
            clen = find_content_length(req, hdr_end);
            if (clen < 0) clen = 0;
            if ((unsigned long)clen > MAX_INPUT) {
                respond_error(fd, 413, "Payload Too Large", "Input exceeds 1 MB limit");
                free(req);
                return;
            }
            need = hdr_end + (size_t)clen;
        }
        if (hdr_end && got >= need) break;
    }

    if (!hdr_end || got < need ||
        sscanf(req, "%7s %2047s", method, target) != 2) {
        respond_error(fd, 400, "Bad Request", "Malformed or incomplete request");
        free(req);
        return;
    }

    q = strchr(target, '?');
    if (q) *q = '\0';

    body = req + hdr_end;
    body[clen] = '\0';

    if (strcmp(target, "/") == 0 || strcmp(target, "/index.html") == 0) {
        if (strcmp(method, "GET") == 0) serve_index(fd);
        else respond_error(fd, 405, "Method Not Allowed", "Use GET");
    } else if (strcmp(target, "/api/health") == 0) {
        respond_json(fd, 200, "OK", "{\"status\":\"ok\"}");
    } else if (strcmp(target, "/api/analyze") == 0) {
        if (strcmp(method, "POST") == 0) handle_analyze(fd, body);
        else respond_error(fd, 405, "Method Not Allowed", "Use POST");
    } else {
        respond_error(fd, 404, "Not Found", "Not found");
    }
    free(req);
}

/* ------------------------------------------------------------ thread per client */
static THREAD_RET client_thread(thread_arg arg)
{
    sock_t fd = (sock_t)(size_t)arg;

#ifdef _WIN32
    DWORD tv = 5000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
#else
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#endif

    handle_connection(fd);
    CLOSE_SOCK(fd);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int spawn(sock_t fd)
{
#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 0, client_thread, (LPVOID)(size_t)fd, 0, NULL);
    if (!h) return -1;
    CloseHandle(h);
    return 0;
#else
    pthread_t t;
    if (pthread_create(&t, NULL, client_thread, (void *)(size_t)fd) != 0) return -1;
    pthread_detach(t);
    return 0;
#endif
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : DEFAULT_PORT;
    sock_t srv;
    struct sockaddr_in addr;
    int on = 1;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { fprintf(stderr, "WSAStartup failed\n"); return 1; }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == BAD_SOCK) { perror("socket"); return 1; }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof on);

    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* localhost only */
    addr.sin_port        = htons((unsigned short)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(srv, 64) < 0) {
        perror("bind/listen (is the port already in use?)");
        return 1;
    }
    printf("Log Analyzer running at http://127.0.0.1:%d  (Ctrl+C to stop)\n", port);
    fflush(stdout);

    for (;;) {
        sock_t fd = accept(srv, NULL, NULL);
        if (fd == BAD_SOCK) continue;
        if (spawn(fd) != 0) CLOSE_SOCK(fd);
    }
    return 0;
}
