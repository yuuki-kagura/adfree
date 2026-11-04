/*
 * Forced client-port collision, to watch how the tunnel answers it.
 *
 *   usage: dport <bound_port> <dst_port> <host> [host...]
 *   NOPROBE=1 : open the sockets but send no byte, so what happens is decided
 *               only by whatever the tunnel answers the SYN with.
 *
 * The engine keys its relay table by the client's source port alone, and the
 * kernel will hand that port to a socket bound for any other address while a
 * first flow still holds it. That is not something a ramp can be asked to
 * produce by chance, so this asks for it directly: one socket per host, every
 * one bound to the same local port, opened in turn.
 *
 * Each line names what the connect cost and how the socket fared after it:
 *
 *   open,<i>,<host>,<elapsed_ms>,<errno or 0>,<peer from getpeername>
 *   t<secs>,<i>,<recv result>,<errno>,<peer>
 *
 * A collision the tunnel can serve answers in milliseconds and the socket keeps
 * reading. A collision it answers with a refusal the client's stack discards is
 * not visible at connect time either: connect() said success and nothing ever
 * comes back, which is the difference between a request that fails fast and a
 * request that hangs.
 *
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang \
 *     -O2 -Wall -o dport bench/dport.c
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_HOSTS 16
#define CONNECT_TIMEOUT_MS 4000

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int connect_nb(int fd, const struct sockaddr *sa, socklen_t len, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (connect(fd, sa, len) != 0 && errno != EINPROGRESS) return -errno;
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    int ready;
    do {
        ready = poll(&pfd, 1, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready == 0) return -ETIMEDOUT;
    int so_error = 0;
    socklen_t n = sizeof so_error;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &n);
    return so_error == 0 ? 0 : -so_error;
}

static void peer_name(int fd, char *out, size_t n) {
    struct sockaddr_in p;
    socklen_t plen = sizeof p;
    snprintf(out, n, "-");
    if (getpeername(fd, (struct sockaddr *)&p, &plen) == 0)
        inet_ntop(AF_INET, &p.sin_addr, out, n);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <bound_port> <dst_port> <host> [host...]\n", argv[0]);
        return 2;
    }
    const int bound_port = atoi(argv[1]);
    char dst_port[8];
    snprintf(dst_port, sizeof dst_port, "%d", atoi(argv[2]));
    const int hosts = argc - 3;
    if (hosts > MAX_HOSTS) return 2;
    const char *np = getenv("NOPROBE");
    const int noprobe = np && np[0] != (char)0 && np[0] != (char)48;

    int fds[MAX_HOSTS];
    for (int i = 0; i < hosts; i++) {
        struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *ai = NULL;
        if (getaddrinfo(argv[3 + i], dst_port, &hints, &ai) != 0 || ai == NULL) {
            printf("open,%d,%s,-1,resolve_failed,-\n", i, argv[3 + i]);
            fds[i] = -1;
            continue;
        }
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons((uint16_t)bound_port)};
        if (bind(fd, (struct sockaddr *)&local, sizeof local) != 0) {
            printf("open,%d,%s,-1,bind_%d,-\n", i, argv[3 + i], errno);
            close(fd);
            fds[i] = -1;
            freeaddrinfo(ai);
            continue;
        }
        double t0 = now_ms();
        int err = connect_nb(fd, ai->ai_addr, ai->ai_addrlen, CONNECT_TIMEOUT_MS);
        double ms = now_ms() - t0;
        char peer[64];
        peer_name(fd, peer, sizeof peer);
        if (err == 0 && !noprobe) {
            /* One byte, so the tunnel has something to classify. */
            const char probe = '\n';
            send(fd, &probe, 1, MSG_NOSIGNAL | MSG_DONTWAIT);
        } else if (err != 0) {
            close(fd);
            fd = -1;
        }
        printf("open,%d,%s,%d,%d,%s%s\n", i, argv[3 + i], (int)ms, -err, peer,
               noprobe ? ",noprobe" : "");
        fflush(stdout);
        fds[i] = fd;
        freeaddrinfo(ai);
    }

    /* A refusal the client's stack discards is not visible at connect time, so
     * say what a read on each socket returns as the seconds go by. */
    int marks[] = {2, 4, 6};
    int elapsed = 0;
    for (unsigned m = 0; m < sizeof marks / sizeof *marks; m++) {
        sleep(marks[m] - elapsed);
        elapsed = marks[m];
        for (int i = 0; i < hosts; i++) {
            if (fds[i] < 0) continue;
            char buf[256];
            ssize_t r = recv(fds[i], buf, sizeof buf, MSG_DONTWAIT);
            char peer[64];
            peer_name(fds[i], peer, sizeof peer);
            if (r > 0)
                printf("t%d,%d,data_%zd,-,%s\n", marks[m], i, r, peer);
            else if (r == 0)
                printf("t%d,%d,eof,-,%s\n", marks[m], i, peer);
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("t%d,%d,again,-,%s\n", marks[m], i, peer);
            else
                printf("t%d,%d,closed,%d,%s\n", marks[m], i, errno, peer);
            fflush(stdout);
        }
    }
    for (int i = 0; i < hosts; i++)
        if (fds[i] >= 0) close(fds[i]);
    return 0;
}
