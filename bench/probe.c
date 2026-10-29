/*
 * In-process latency probe for the tunnel benchmark.
 *
 * `nc -z` from the adb shell costs ~50 ms of fork/exec per probe on the test
 * device, which swamps what the tunnel adds. This binary resolves and connects
 * in one process and reports the two halves separately:
 *
 *   round,host,gai,rc,addr,dns_ms,connect_ms,total_ms
 *
 * `gai` is getaddrinfo's code (0 = resolved), `rc` the connect result (0 or
 * errno), `dns_ms` includes netd, the VPN's DNS path and the answer, and
 * `connect_ms` is the TCP handshake through the tunnel.
 *
 * Build (arm64 device). Do not link statically: a static binary cannot reach
 * netd's DNS proxy, and every lookup fails with EAI_NODATA (gai=7).
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang \
 *     -O2 -o probe bench/probe.c
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
#include <time.h>
#include <unistd.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* Non-blocking connect with a deadline: a blocked host must not stall the run. */
static int connect_ms(const struct addrinfo *ai, int timeout_ms, double *took) {
    int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) return -errno;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    double t0 = now_ms();
    int rc = 0;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        if (errno != EINPROGRESS) {
            rc = -errno;
        } else {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            int ready;
            do {
                ready = poll(&pfd, 1, timeout_ms);
            } while (ready < 0 && errno == EINTR);
            if (ready == 0) {
                rc = -ETIMEDOUT;
            } else {
                int so_error = 0;
                socklen_t len = sizeof so_error;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                rc = so_error == 0 ? 0 : -so_error;
            }
        }
    }
    *took = now_ms() - t0;
    close(fd);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rounds> <host> [host...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    printf("round,host,gai,rc,addr,dns_ms,connect_ms,total_ms\n");

    for (int r = 0; r < rounds; r++) {
        for (int i = 2; i < argc; i++) {
            const char *host = argv[i];
            char addr[INET6_ADDRSTRLEN] = "-";

            double t0 = now_ms();
            struct addrinfo hints;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            struct addrinfo *res = NULL;
            int gai = getaddrinfo(host, "443", &hints, &res);
            double t1 = now_ms();

            int rc = -1;
            double connect = 0.0;
            if (gai == 0 && res != NULL) {
                const struct addrinfo *ai = res;
                if (ai->ai_family == AF_INET) {
                    inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
                              addr, sizeof addr);
                } else {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                              addr, sizeof addr);
                }
                rc = connect_ms(ai, 2000, &connect);
                freeaddrinfo(res);
            }
            double t2 = now_ms();
            printf("%d,%s,%d,%d,%s,%.1f,%.1f,%.1f\n", r, host, gai, rc, addr,
                   t1 - t0, connect, t2 - t0);
            fflush(stdout);
        }
    }
    return 0;
}
