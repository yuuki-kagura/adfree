//! Hot counters.
//!
//! Every counter is a relaxed atomic, so the packet thread can bump them with a
//! single `lock xadd` and no cache line ping-pong with the JNI thread that
//! samples them once a second.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    pub packets_total: AtomicU64,
    pub packets_dns: AtomicU64,
    pub packets_forwarded: AtomicU64,
    /// Synthetic answers produced locally (blocked at DNS level).
    pub dns_blocked: AtomicU64,
    pub dns_allowed: AtomicU64,
    /// Connections killed before any upstream byte was spent.
    pub tcp_reset: AtomicU64,
    /// Connections the engine took over (every TCP flow is relayed).
    pub tcp_relayed: AtomicU64,
    /// Packets dropped (QUIC, DoT, blocked IPs).
    pub dropped: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_replies: AtomicU64,
    pub dns_timeouts: AtomicU64,
    pub quic_dropped: AtomicU64,
    pub udp_dropped: AtomicU64,
    /// UDP datagrams spliced through a NAT mapping, both directions.
    pub udp_relayed: AtomicU64,
    /// Estimated bytes saved: blocked requests never reach the network.
    pub bytes_saved: AtomicU64,
    /// Sum of per-decision latencies (nanoseconds) and the worst one seen.
    pub decision_ns_sum: AtomicU64,
    pub decision_ns_max: AtomicU64,
    pub decision_count: AtomicU64,
    /// Steady-state latency (EWMA): the first decisions pay for engine warm-up
    /// and would otherwise skew the average forever.
    pub decision_ns_ewma: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub filter_rules: AtomicU64,
    pub engine_bytes: AtomicU64,
    /// Difference between two reads of this is the RSS delta snapshot from
    /// `/proc/self/statm`.
    pub rss_kb: AtomicU64,
    /// Loop wakeups (packet reads) and total microseconds spent inside
    /// `process_packet`, used to show how little CPU the engine actually burns.
    pub loop_iterations: AtomicU64,
    pub busy_ns: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Stats::default()
    }

    #[inline]
    pub fn inc(&self, c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(&self, c: &AtomicU64, v: u64) {
        c.fetch_add(v, Ordering::Relaxed);
    }

    #[inline]
    pub fn set(&self, c: &AtomicU64, v: u64) {
        c.store(v, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self, c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    /// Zeroes everything. Used when the user asks for the stats to be reset.
    pub fn reset(&self) {
        for counter in [
            &self.packets_total,
            &self.packets_dns,
            &self.packets_forwarded,
            &self.dns_blocked,
            &self.dns_allowed,
            &self.tcp_reset,
            &self.tcp_relayed,
            &self.dropped,
            &self.dns_queries,
            &self.dns_replies,
            &self.dns_timeouts,
            &self.quic_dropped,
            &self.udp_dropped,
            &self.udp_relayed,
            &self.bytes_saved,
            &self.decision_ns_sum,
            &self.decision_ns_max,
            &self.decision_count,
            &self.cache_hits,
            &self.loop_iterations,
            &self.busy_ns,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Records one filter decision.
    #[inline]
    pub fn record_decision(&self, ns: u64) {
        self.decision_ns_sum.fetch_add(ns, Ordering::Relaxed);
        self.decision_count.fetch_add(1, Ordering::Relaxed);
        // EWMA with a 1/8 weight: reacts within a few decisions.
        let mut current = self.decision_ns_ewma.load(Ordering::Relaxed);
        if current == 0 {
            current = ns;
        } else {
            current = (current * 7 + ns) / 8;
        }
        self.decision_ns_ewma.store(current, Ordering::Relaxed);
        let mut current = self.decision_ns_max.load(Ordering::Relaxed);
        while ns > current {
            match self.decision_ns_max.compare_exchange_weak(
                current,
                ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let count = self.get(&self.decision_count);
        let sum = self.get(&self.decision_ns_sum);
        StatsSnapshot {
            packets_total: self.get(&self.packets_total),
            packets_dns: self.get(&self.packets_dns),
            packets_forwarded: self.get(&self.packets_forwarded),
            dns_blocked: self.get(&self.dns_blocked),
            dns_allowed: self.get(&self.dns_allowed),
            tcp_reset: self.get(&self.tcp_reset),
            tcp_relayed: self.get(&self.tcp_relayed),
            quic_dropped: self.get(&self.quic_dropped),
            udp_dropped: self.get(&self.udp_dropped),
            udp_relayed: self.get(&self.udp_relayed),
            dropped: self.get(&self.dropped),
            dns_queries: self.get(&self.dns_queries),
            dns_replies: self.get(&self.dns_replies),
            dns_timeouts: self.get(&self.dns_timeouts),
            bytes_saved: self.get(&self.bytes_saved),
            decision_ns_avg: sum.checked_div(count).unwrap_or(0),
            decision_ns_ewma: self.get(&self.decision_ns_ewma),
            decision_ns_max: self.get(&self.decision_ns_max),
            cache_hits: self.get(&self.cache_hits),
            cache_misses: self.get(&self.cache_misses),
            filter_rules: self.get(&self.filter_rules),
            engine_bytes: self.get(&self.engine_bytes),
            rss_kb: self.get(&self.rss_kb),
            loop_iterations: self.get(&self.loop_iterations),
            busy_ns: self.get(&self.busy_ns),
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct StatsSnapshot {
    pub packets_total: u64,
    pub packets_dns: u64,
    pub packets_forwarded: u64,
    pub dns_blocked: u64,
    pub dns_allowed: u64,
    pub tcp_reset: u64,
    pub tcp_relayed: u64,
    pub dropped: u64,
    pub dns_queries: u64,
    pub dns_replies: u64,
    pub dns_timeouts: u64,
    pub quic_dropped: u64,
    pub udp_dropped: u64,
    pub udp_relayed: u64,
    pub bytes_saved: u64,
    pub decision_ns_avg: u64,
    pub decision_ns_ewma: u64,
    pub decision_ns_max: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub filter_rules: u64,
    pub engine_bytes: u64,
    pub rss_kb: u64,
    pub loop_iterations: u64,
    pub busy_ns: u64,
}

/// Reads the resident set size of this process from `/proc/self/statm`.
pub fn read_rss_kb() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let pages: u64 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    pages * 4 // 4 KiB pages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_snapshot() {
        let s = Stats::new();
        s.inc(&s.packets_total);
        s.add(&s.packets_total, 41);
        s.record_decision(1_000);
        s.record_decision(3_000);
        s.record_decision(500);
        let snap = s.snapshot();
        assert_eq!(snap.packets_total, 42);
        assert_eq!(snap.decision_ns_avg, 1_500);
        assert_eq!(snap.decision_ns_max, 3_000);
    }

    #[test]
    fn reads_rss() {
        assert!(read_rss_kb() > 0);
    }
}
