//! HTTP/3 filtering: QUIC termination and re-origination.
//!
//! The TUN device is the only network interface this process owns, so neither
//! the client-facing nor the upstream QUIC endpoint may open a real socket.
//! `socket::TunUdpSocket` carries datagrams to and from the packet engine
//! in memory; everything above it is ordinary quinn/h3.

pub mod bridge;
pub mod hub;
pub mod socket;
