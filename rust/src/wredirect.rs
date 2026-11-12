//! The Windows redirect as the application sees it: on, off, and the counters.
//!
//! On Linux the "redirect" is a rule table the platform layer installs, so this
//! module has nothing to say there and says so: [`start`] answers with a
//! sentence, not a silent success. On Windows it owns the driver loop — one
//! thread, two handles, one table — and hands the UI the numbers the tray
//! tooltip shows.

use std::sync::Mutex;

/// What the redirect is doing, as the UI asks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectStatus {
    pub running: bool,
    pub packets_seen: u64,
    pub live_flows: u64,
}

struct Running {
    stop: Box<dyn Fn() + Send + Sync>,
    status: Box<dyn Fn() -> (u64, usize) + Send + Sync>,
    thread: std::thread::JoinHandle<()>,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// Starts the redirect towards the local proxy and resolver.
///
/// Idempotent: a second call while it runs is not an error, because the caller
/// is usually "protection went on" and protection can be asked for twice.
pub fn start(proxy_port: u16, dns_port: u16) -> Result<(), String> {
    #[cfg(windows)]
    {
        use crate::sys::windivert;
        use crate::winnat::Endpoint;
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;

        let mut slot = RUNNING.lock().map_err(|_| "redirect lock poisoned")?;
        if slot.is_some() {
            return Ok(());
        }
        let proxy = Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port);
        let dns = Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dns_port);
        let redirector = windivert::Redirector::start(proxy, dns)?;
        let inner = Arc::clone(&redirector);
        let thread = std::thread::Builder::new()
            .name("adfree-redirect".to_string())
            .spawn(move || windivert::run(&inner))
            .map_err(|e| format!("cannot start the redirect thread: {e}"))?;
        let stop_target = Arc::clone(&redirector);
        let status_target = Arc::clone(&redirector);
        *slot = Some(Running {
            stop: Box::new(move || stop_target.stop()),
            status: Box::new(move || {
                (status_target.packets_seen(), status_target.live_mappings())
            }),
            thread,
        });
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (proxy_port, dns_port);
        Err("the driver redirect exists only on Windows; Linux uses nftables".to_string())
    }
}

/// Ends the redirect and waits for its thread. Safe to call when it is not
/// running, which is what "protection off" turns into.
pub fn stop() {
    let running = {
        let mut slot = match RUNNING.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        slot.take()
    };
    if let Some(running) = running {
        (running.stop)();
        // The loop may still be inside the driver's `recv`; closing the handles
        // is what releases it.
        let _ = running.thread.join();
    }
}

pub fn status() -> RedirectStatus {
    let slot = match RUNNING.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    match slot.as_ref() {
        Some(running) => {
            let (packets_seen, live_flows) = (running.status)();
            RedirectStatus {
                running: true,
                packets_seen,
                live_flows: live_flows as u64,
            }
        }
        None => RedirectStatus {
            running: false,
            packets_seen: 0,
            live_flows: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_a_platform_without_the_driver_starting_says_so() {
        #[cfg(not(windows))]
        {
            assert!(start(3129, 5300).is_err());
            assert!(!status().running);
            // Stopping something that never started is not an error.
            stop();
        }
    }

    #[test]
    fn status_is_quiet_before_and_after_stop() {
        stop();
        let s = status();
        assert!(!s.running);
        assert_eq!(s.packets_seen, 0);
        assert_eq!(s.live_flows, 0);
    }
}
