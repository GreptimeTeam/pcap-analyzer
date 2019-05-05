use crate::three_tuple::ThreeTuple;
use std::net::{IpAddr, Ipv4Addr};

/// Network 5-tuple: layer 4 protocol (e.g TCP or UDP), source and destination IP/ports
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FiveTuple {
    /// Layer 4 protocol (e.g TCP, UDP, ICMP)
    pub proto: u8,
    /// Source IP address
    pub src: IpAddr,
    /// Destination IP address
    pub dst: IpAddr,
    /// Source port. 0 if not relevant for protocol
    pub src_port: u16,
    /// Destination port. 0 if not relevant for protocol
    pub dst_port: u16,
}

/// Generic interface for structures that can provide a `FiveTuple`
pub trait ToFiveTuple {
    /// Returns the `FiveTuple`
    fn get_five_tuple(&self) -> FiveTuple;
}

impl FiveTuple {
    /// Creates a `FiveTuple` from a `ThreeTuple` and the source/destination ports
    pub fn from_three_tuple(t3: &ThreeTuple, src_port: u16, dst_port: u16) -> Self {
        FiveTuple {
            proto: t3.proto,
            src: t3.src,
            dst: t3.dst,
            src_port,
            dst_port,
        }
    }
    /// Returns the opposite `FiveTuple` (swaps IP addresses, and ports)
    pub fn get_reverse(&self) -> FiveTuple {
        FiveTuple {
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl Default for FiveTuple {
    fn default() -> Self {
        FiveTuple {
            proto: 0,
            src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: 0,
            dst_port: 0,
        }
    }
}