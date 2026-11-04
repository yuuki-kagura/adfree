/*
 * Concurrent-flow harness for the on-device per-flow memory probe.
 *
 *   usage: flows <step> <stages> <hold_s> <idle|nudge|http> <port> <host> [host...]
 *
 * `bench/probe.c` answers "how long does one flow take"; this answers "what does
 * a live flow cost the tunnel process". Stage 1 opens `step` connections and
 * holds them for `hold_s`, stage 2 holds `2 * step`, and so on, so the memory
 * curve is a staircase with a known number of flows on each tread.
 *
 * Holding is not passive. Every half second each socket is drained and then
 * probed with a non-blocking read, so a socket whose peer (or the tunnel itself)
 * has gone away is closed and replaced and the stage's target concurrency is
 * actually met for the whole window instead of decaying. The drain is not
 * decoration: `http` mode leaves a HEAD answer sitting in every buffer, and a
 * socket with data pending never reports the FIN behind it — a stage then looks
 * full while the tunnel has already dropped most of its relays. A non-TLS byte
 * on port 443 is the other case: with HTTPS filtering armed the tunnel gives up
 * on the flow after about fifteen seconds, and without the top-up the
 * concurrency at the end of a hold is a fraction of what the stage asked for.
 * The live count is printed every five seconds, and the driver counts
 * established sockets on both halves from `/proc/net/tcp`, so the regression is
 * against observed relays rather than requested connections.
 *
 * Output, flushed as it happens:
 *
 *   stage,<index>,<live>,<opened>,<missed>,<hold_s>
 *   hold,<index>,<live>,<opened>,<missed>,<elapsed_s>
 *   released,0,0,<opened>,<missed>,<hold_s>
 *
 * `idle` leaves a new socket silent; `nudge` writes one byte down it, so the
 * engine has something to classify; `http` sends `HEAD / HTTP/1.1` with
 * `Connection: keep-alive` on open and again every ten seconds, which is what
 * keeps a real relay alive on the filtered path — the engine dials the origin
 * only once it can match a request line, so an idle socket is not the same
 * object as a live flow. `HEAD` keeps the answer to headers, so the measurement
 * is not padded by page bodies sitting in socket buffers.
 *
 * Run it as a uid the tunnel captures. On a debug build `files/capture-shell`
 * lets the shell in — but the marker is read when the tunnel is built, so
 * protection has to be restarted after it is written, and `dumpsys
 * connectivity` is what says whether the live `Uids:` range still has a hole at
 * 2000. Running from a captured app uid instead takes the question out of the
 * run entirely; that path needs the binary in the app's own data directory,
 * because `/data/local/tmp` is not executable under `run-as`.
 *
 * Traffic to the local subnet is not captured either way — Android keeps a VPN
 * off the LAN unless the app holds ACCESS_LOCAL_NETWORK — so the hosts here must
 * be real internet addresses.
 *
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang \
 *     -O2 -Wall -o flows bench/flows.c
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_HOSTS 64
#define POKE_EVERY_MS 10000.0
#define GIVE_UP_AFTER 300

enum { MODE_IDLE, MODE_NUDGE, MODE_HTTP };

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

/* 1 while the socket still has a peer. A kept-alive connection always has an
 * unread HEAD answer sitting in its buffer, and a socket with data pending never
 * reports the close that follows it, so the answer is drained here before the
 * state of the socket means anything. */
static int alive(int fd) {
    char buf[512];
    for (int rounds = 0; rounds < 64; rounds++) {
        ssize_t r = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (r > 0) continue;
        if (r == 0) return 0;
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }
    return 1;
}

/* The bytes that make a socket a flow the engine can act on. */
static void poke(int fd, const char *name, int mode) {
    if (mode == MODE_IDLE) return;
    char req[256];
    int len;
    if (mode == MODE_HTTP) {
        len = snprintf(req, sizeof req,
                       "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: adfree-bench\r\n"
                       "Accept: */*\r\nConnection: keep-alive\r\n\r\n", name);
    } else {
        len = 1;
        req[0] = '\n';
    }
    if (len > 0) send(fd, req, (size_t)len, MSG_NOSIGNAL | MSG_DONTWAIT);
}

/* One connection, or -1 once GIVE_UP_AFTER attempts in a row have missed. */
static int open_flow(struct addrinfo **addrs, const char **names, int hosts, int mode,
                     int *attempts, int *host_of, int *missed) {
    for (int tries = 0; tries < GIVE_UP_AFTER; tries++) {
        int h = (*attempts)++ % hosts;
        struct addrinfo *ai = addrs[h];
        if (ai == NULL) {
            (*missed)++;
            continue;
        }
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            (*missed)++;
            continue;
        }
        if (connect_nb(fd, ai->ai_addr, ai->ai_addrlen, 2000) != 0) {
            close(fd);
            (*missed)++;
            continue;
        }
        poke(fd, names[h], mode);
        *host_of = h;
        return fd;
    }
    return -1;
}

/* Raise live to target, so a stage is measured at the concurrency it asked for. */
static void fill(int *fds, int *host_of, int *live, int target, int capacity,
                 struct addrinfo **addrs, const char **names, int hosts, int mode,
                 int *attempts, int *opened, int *missed) {
    while (*live < target && *live < capacity) {
        int h = 0;
        int fd = open_flow(addrs, names, hosts, mode, attempts, &h, missed);
        if (fd < 0) return;
        fds[*live] = fd;
        host_of[*live] = h;
        (*live)++;
        (*opened)++;
    }
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
                "usage: %s <step> <stages> <hold_s> <idle|nudge|http> <port> <host> [host...]\n",
                argv[0]);
        return 2;
    }
    const int step = atoi(argv[1]);
    const int stages = atoi(argv[2]);
    const int hold_s = atoi(argv[3]);
    const int mode = strcmp(argv[4], "http") == 0 ? MODE_HTTP
                     : strcmp(argv[4], "idle") == 0 ? MODE_IDLE
                     : MODE_NUDGE;
    char port[8];
    snprintf(port, sizeof port, "%d", atoi(argv[5]));
    const int hosts = argc - 6;
    if (hosts > MAX_HOSTS) {
        fprintf(stderr, "too many hosts (max %d)\n", MAX_HOSTS);
        return 2;
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max > rl.rlim_cur) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    /* Resolve each host once up front: a stage must not be paced by DNS. */
    struct addrinfo *addrs[MAX_HOSTS];
    const char *names[MAX_HOSTS];
    int resolved = 0;
    for (int i = 0; i < hosts; i++) {
        names[i] = argv[6 + i];
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int gai = getaddrinfo(argv[6 + i], port, &hints, &addrs[i]);
        if (gai != 0) {
            fprintf(stderr, "resolve %s: %s\n", argv[6 + i], gai_strerror(gai));
            addrs[i] = NULL;
        } else {
            resolved++;
        }
    }
    if (resolved == 0) {
        fprintf(stderr, "nothing resolved\n");
        return 2;
    }

    int capacity = step * stages;
    int *fds = calloc(capacity, sizeof *fds);
    int *host_of = calloc(capacity, sizeof *host_of);
    int live = 0, opened = 0, missed = 0, attempts = 0;

    for (int s = 1; s <= stages; s++) {
        int target = step * s;
        fill(fds, host_of, &live, target, capacity, addrs, names, hosts, mode,
             &attempts, &opened, &missed);

        printf("stage,%d,%d,%d,%d,%d\n", s, live, opened, missed, hold_s);
        fflush(stdout);

        double start = now_ms();
        double last_report = start;
        double last_poke = start;
        while (now_ms() - start < hold_s * 1000.0) {
            usleep(500000);
            for (int i = 0; i < live;) {
                if (alive(fds[i])) {
                    i++;
                    continue;
                }
                close(fds[i]);
                live--;
                fds[i] = fds[live];
                host_of[i] = host_of[live];
            }
            if (mode == MODE_HTTP && now_ms() - last_poke >= POKE_EVERY_MS) {
                for (int i = 0; i < live; i++) poke(fds[i], names[host_of[i]], MODE_HTTP);
                last_poke = now_ms();
            }
            fill(fds, host_of, &live, target, capacity, addrs, names, hosts, mode,
                 &attempts, &opened, &missed);
            if (now_ms() - last_report >= 5000.0) {
                printf("hold,%d,%d,%d,%d,%d\n", s, live, opened, missed,
                       (int)((now_ms() - start) / 1000.0));
                fflush(stdout);
                last_report = now_ms();
            }
        }
    }

    for (int i = 0; i < live; i++) close(fds[i]);
    printf("released,0,0,%d,%d,%d\n", opened, missed, hold_s);
    fflush(stdout);

    for (int i = 0; i < hosts; i++) freeaddrinfo(addrs[i]);
    free(fds);
    free(host_of);
    return 0;
}
