// What one `poll()` over a large wait set costs, measured on its own.
//
// This is the baseline the `epoll` port was argued from, kept so the number can be
// re-taken. The forwarder used to rebuild a `Vec<pollfd>` of every relay and NAT
// descriptor and hand it to `poll()` on each pass, so the wait was O(relays) twice
// over: the kernel copied the array in, scanned it, and copied the results out.
// `rust/src/waitset.rs` replaced that on 04/11/2026; this asks what the scan cost
// per call with no engine in the way.
//
// usage: pollcost [nfds] [iters] [ready]
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

int main(int argc, char **argv) {
    int nfds = argc > 1 ? atoi(argv[1]) : 2048;
    int iters = argc > 2 ? atoi(argv[2]) : 20000;
    int ready = argc > 3 ? atoi(argv[3]) : 0;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
            fprintf(stderr, "setrlimit: %s (continuing)\n", strerror(errno));
    }

    struct pollfd *pfd = calloc(nfds, sizeof *pfd);
    int *peer = calloc(nfds, sizeof *peer);
    if (!pfd || !peer) return 2;

    for (int i = 0; i < nfds; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fprintf(stderr, "socketpair at %d: %s\n", i, strerror(errno));
            nfds = i;
            break;
        }
        pfd[i].fd = sv[0];
        pfd[i].events = POLLIN;
        peer[i] = sv[1];
    }
    // Make exactly `ready` descriptors readable, the way a pass finds a handful
    // of relays with an answer waiting.
    for (int i = 0; i < ready && i < nfds; i++) {
        char b = 'x';
        if (write(peer[i], &b, 1) != 1) fprintf(stderr, "prime %d failed\n", i);
    }

    // Warm the set once, then time the calls. `timeout 0` keeps the wait out of
    // the measurement: this is the copy-scan-copy cost, not sleeping.
    int rc = poll(pfd, nfds, 0);
    double t0 = now_ns();
    long hits = 0;
    for (int i = 0; i < iters; i++) {
        for (int j = 0; j < nfds; j++) pfd[j].revents = 0;
        rc = poll(pfd, nfds, 0);
        if (rc > 0) hits += rc;
    }
    double dt = now_ns() - t0;
    printf("nfds=%d iters=%d ready=%d  %.2f us per poll()  (rc=%d hits=%ld)\n",
           nfds, iters, ready, dt / iters / 1000.0, rc, hits);
    return 0;
}
