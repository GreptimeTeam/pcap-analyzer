use std::net::IpAddr;

use log::warn;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

use libpcap_tools::{Error, FiveTuple, ParseContext};

use super::fragmentation::fragmentation_test;
use super::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use super::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPort;
use crate::filters::fragmentation::key_fragmentation_matching::KeyFragmentationMatching;
use crate::filters::ipaddr_pair::IpAddrPair;

pub fn parse_src_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv4 = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;
    Result::Ok(IpAddr::V4(ipv4.get_source()))
}

pub fn parse_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv4 = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    Result::Ok(IpAddr::V4(ipv4.get_destination()))
}

pub fn parse_src_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddrPair, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());
    Result::Ok(IpAddrPair::new(src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<Option<IpAddrProtoPort>, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 20 && ipv4_packet.get_fragment_offset() == 0 {
                match TcpPacket::new(ipv4_payload) {
                    Some(ref tcp) => {
                        let dst_port = tcp.get_destination();
                        Ok(Some(IpAddrProtoPort::new(
                            src_ipaddr,
                            IpNextHeaderProtocols::Tcp,
                            dst_port,
                        )))
                    }
                    None => {
                        warn!(
                            "Expected TCP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected TCP packet in Ipv4 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(None)
            }
        }
        IpNextHeaderProtocols::Udp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 20 && ipv4_packet.get_fragment_offset() == 0 {
                match UdpPacket::new(ipv4_packet.payload()) {
                    Some(ref udp) => {
                        let dst_port = udp.get_destination();
                        Ok(Some(IpAddrProtoPort::new(
                            src_ipaddr,
                            IpNextHeaderProtocols::Udp,
                            dst_port,
                        )))
                    }
                    None => {
                        warn!(
                            "Expected UDP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected UDP packet in Ipv4 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(None)
            }
        }
        _ => Ok(Some(IpAddrProtoPort::new(
            src_ipaddr,
            ipv4_packet.get_next_level_protocol(),
            0,
        ))),
    }
}

pub fn parse_two_tuple_proto_ipid(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpid, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());
    let proto = ipv4_packet.get_next_level_protocol().0;
    let ip_id = ipv4_packet.get_identification() as u32;
    Ok(TwoTupleProtoIpid::new(src_ipaddr, dst_ipaddr, proto, ip_id))
}

/// Extract a FiveTuple from a payload.
/// The return type is an option to encode insufficent transport payload.
pub fn parse_five_tuple(ctx: &ParseContext, payload: &[u8]) -> Result<Option<FiveTuple>, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 20 && ipv4_packet.get_fragment_offset() == 0 {
                match TcpPacket::new(ipv4_payload) {
                    Some(ref tcp) => {
                        let src_port = tcp.get_source();
                        let dst_port = tcp.get_destination();
                        Ok(Some(FiveTuple {
                            src: src_ipaddr,
                            dst: dst_ipaddr,
                            proto: 6_u8,
                            src_port,
                            dst_port,
                        }))
                    }
                    None => {
                        warn!(
                            "Expected TCP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected TCP packet in Ipv4 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(None)
            }
        }
        IpNextHeaderProtocols::Udp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 8 && ipv4_packet.get_fragment_offset() == 0 {
                match UdpPacket::new(ipv4_payload) {
                    Some(ref udp) => {
                        let src_port = udp.get_source();
                        let dst_port = udp.get_destination();
                        Ok(Some(FiveTuple {
                            src: src_ipaddr,
                            dst: dst_ipaddr,
                            proto: 17_u8,
                            src_port,
                            dst_port,
                        }))
                    }
                    None => {
                        warn!(
                            "Expected UDP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected UDP packet in Ipv4 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(None)
            }
        }
        _ => Ok(Some(FiveTuple {
            src: src_ipaddr,
            dst: dst_ipaddr,
            proto: ipv4_packet.get_next_level_protocol().0,
            src_port: 0,
            dst_port: 0,
        })),
    }
}

/// Parse both TwoTupleProtoIpid and FiveTuple.
/// This function is used when parsing the first fragment.
pub fn parse_two_tuple_proto_ipid_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpidFiveTuple, Error> {
    Ok(TwoTupleProtoIpidFiveTuple::new(
        Some(parse_two_tuple_proto_ipid(ctx, payload)?),
        // TODO: replace by dedicated error type to distinguish between Ipv6Packet parsing error and TcpPacket/UdpPacket error related to fragmentation
        parse_five_tuple(ctx, payload)?,
    ))
}

/// Parse Key and then, if Key parsing was not possible, parse TwoTupleProtoIpid.
/// This functions is used when trying to find packet related to a first fragment.
pub fn parse_key_fragmentation_transport<Key>(
    key_parse: fn(&ParseContext, &[u8]) -> Result<Option<Key>, Error>,
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<KeyFragmentationMatching<Option<Key>>, Error> {
    if fragmentation_test::is_ipv4_fragment(ctx, payload)? {
        let two_tuple_proto_ipid = parse_two_tuple_proto_ipid(ctx, payload)?;
        if fragmentation_test::is_ipv4_first_fragment(ctx, payload)? {
            match key_parse(ctx, payload)? {
                Some(key) => Ok(KeyFragmentationMatching::FirstFragment(
                    two_tuple_proto_ipid,
                    Some(key),
                )),
                // NB
                // This case happens when the first fragment does have enough data to parse transport header.
                // The clean approach would be to a full IP fragmentation reassembly.
                // We hope this case is rare. :)
                None => Ok(KeyFragmentationMatching::FirstFragment(
                    two_tuple_proto_ipid,
                    None,
                )),
            }
        } else {
            Ok(KeyFragmentationMatching::FragmentAfterFirst(
                two_tuple_proto_ipid,
            ))
        }
    } else {
        Ok(KeyFragmentationMatching::NotFragment(key_parse(
            ctx, payload,
        )?))
    }
}

pub fn parse_key_fragmentation_transport_src_ipaddr_proto_dst_port(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<KeyFragmentationMatching<Option<IpAddrProtoPort>>, Error> {
    parse_key_fragmentation_transport(parse_src_ipaddr_proto_dst_port, ctx, payload)
}

pub fn parse_key_fragmentation_transport_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<KeyFragmentationMatching<Option<FiveTuple>>, Error> {
    parse_key_fragmentation_transport(parse_five_tuple, ctx, payload)
}
