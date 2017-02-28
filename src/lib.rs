extern crate pnet;

use pnet::packet::ethernet::{EthernetPacket,EtherTypes};
use pnet::packet::*;
use pnet::packet::vlan::*;
use pnet::packet::ipv4::*;
use pnet::packet::ipv6::*;
use pnet::packet::tcp::*;

use pnet::packet::ip::IpNextHeaderProtocols;

#[derive(Debug)]
enum Protocol {
	Ethernet,
	Vlan { depth: usize },
	Arp,
	Ipv4,
	Ipv6,
	Tcp,
	Udp,
	Icmp,
	Http,
	Ssh,
	Ftp
}

#[derive(Debug)]
struct Wrapper<'a> {
	protocols: Vec<Protocol>,
	packet: &'a [u8],
}

impl<'a> Wrapper<'a> {

	fn decap(ethernet: &'a EthernetPacket, depth: usize) -> Wrapper<'a> {
		let mut w = Wrapper {
			protocols: Vec::with_capacity(depth),
			packet: ethernet.payload()
		};
		let mut offset = 0;
		for _ in 0..depth {
			match w.protocols.last() {
				// Layer 2
				None => {
					w.protocols.push(Protocol::Ethernet);
				}
				Some(&Protocol::Arp) => {
					break
				}
				
				Some(&Protocol::Ethernet) => {
					match ethernet.get_ethertype() {
						EtherTypes::Vlan => {
							w.protocols.push(Protocol::Vlan {depth: 0} );
						}
						EtherTypes::Ipv4 => {
							w.protocols.push(Protocol::Ipv4);
						}
						EtherTypes::Ipv6 => {
							w.protocols.push(Protocol::Ipv6);
						}
						EtherTypes::Arp => {
							w.protocols.push(Protocol::Arp);
						}
						_ => {}
					}
				}
				Some(&Protocol::Vlan { depth }) => {
					let packet = VlanPacket::new(&w.packet[offset..]).unwrap();
					
				
					match packet.get_ethertype() {
						EtherTypes::Vlan => {
							w.protocols.push(Protocol::Vlan {depth: depth + 1 } );
						}
						EtherTypes::Ipv4 => {
							w.protocols.push(Protocol::Ipv4);
						}
						EtherTypes::Ipv6 => {
							w.protocols.push(Protocol::Ipv6);
						}
						EtherTypes::Arp => {
							w.protocols.push(Protocol::Arp);
						}
						_ => { }

					} 
					offset = (depth + 1) * 4;
				}
				// Layer 3
				Some(&Protocol::Ipv4) => {
					let packet = match Ipv4Packet::new(&w.packet[offset..]) {
						Some(packet) => { offset += 20 as usize; packet }
						None => break,
					};
					println!("{} {:?}", offset, packet.get_next_level_protocol());
					
					match packet.get_next_level_protocol() {
						IpNextHeaderProtocols::Tcp => { w.protocols.push(Protocol::Tcp); }
						IpNextHeaderProtocols::Udp => { w.protocols.push(Protocol::Udp); }
						IpNextHeaderProtocols::Icmp => { w.protocols.push(Protocol::Icmp); }
						_ => {}
					}
				}
				Some(&Protocol::Ipv6) => {
					if offset > 0 {offset += 2}
					let packet = match Ipv6Packet::new(&w.packet[offset..]) {
						Some(packet) => { offset += 8; packet }
						None => break,
					};
					
					match packet.get_next_header() {
						IpNextHeaderProtocols::Tcp => { w.protocols.push(Protocol::Tcp); }
						IpNextHeaderProtocols::Udp => { w.protocols.push(Protocol::Udp); }
						IpNextHeaderProtocols::Icmp => { w.protocols.push(Protocol::Icmp); }
						_ => {}
					}
					
				}
				// Layer 4 - 7
				Some(&Protocol::Tcp) => {

					let packet = match TcpPacket::new(&w.packet[offset..]) {
						Some(packet) => { offset += 20 + packet.get_options_raw().len(); packet }
						None => break,
					};
					match (packet.get_source(), packet.get_destination()) {
						(21, _) | (_, 21) => {w.protocols.push(Protocol::Ftp);}
						(22, _) | (_, 22) => {w.protocols.push(Protocol::Ssh);}
						(80, _) | (_, 80) => {w.protocols.push(Protocol::Http);}
						(_, _) => {break}
					}
					
					break	
				}
				Some(&Protocol::Udp) => {
					break	
				}
				Some(&Protocol::Icmp) => {
					println!("akjshdjaksh");
					break	
				}
				Some(&Protocol::Ftp) => {
					break	
				}
				Some(&Protocol::Ssh) => {
					break	
				}
				Some(&Protocol::Http) => {
					break	
				}
			}

		}
		w

	}
}





#[cfg(test)]
mod tests {
	use pnet::packet::ethernet::{EthernetPacket,EtherTypes};
	use super::Wrapper;
    #[test]
    fn test_vlan() {
		let packet = [// Ethernet 
					  0xde, 0xf0, 0x12, 0x34, 0x45, 0x67, /* destination */
                      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, /* source */
					  // 1. Vlan
                      0x81, 0x00, /* ethertype */
                      0x00, 0x00, /* ethertype */
					  // 2. Vlan
                      0x81, 0x00, /* ethertype */
                      0x00, 0x00, /* ethertype */
					  // 3. Vlan
                      0x81, 0x00, /* ethertype */
                      0x00, 0x00, /* ethertype */
					  // 4. Vlan
                      0x81, 0x00, /* ethertype */
                      0x00, 0x00, /* ethertype */
					  0x08, 0x00, 
					  // Ipv4
					  0x45,           /* ver/ihl */
                      0x11,           /* dscp/ecn */
                      0x00, 0x73,     /* total len */
                      0x01, 0x01,     /* identification */
                      0x41, 0x01,     /* flags/frag offset */
                      0x40,           /* ttl */
                      0x06,           /* proto */
                      0xb6, 0x4e,     /* checksum */
                      0xc0, 0xa8, 0x00, 0x01, /* source ip */
                      0xc0, 0xa8, 0x00, 0xc7, /* dest ip */
					  // Tcp
					  0x00, 0x50, /* source */
                      0x23, 0x28, /* destination */
                      0x90, 0x37, 0xd2, 0xb8, /* seq */
                      0x94, 0x4b, 0xb2, 0x76, /* ack */
                      0x80, 0x18, 0x0f, 0xaf, /* length, flags, win */
                      0xc0, 0x31, /* checksum */
                      0x00, 0x00,  /* urg ptr */
                      0x01, 0x01, /* options: nop */
                      0x08, 0x0a, 0x2c, 0x57,
                      0xcd, 0xa5, 0x02, 0xa0,
                      0x41, 0x92, /* timestamp */
                      0x74, 0x65, 0x73, 0x74 /* "test" */
                      ];
			let ethernet = EthernetPacket::new(&packet).unwrap();
			let wrapper = Wrapper::decap(&ethernet, 9);
			
			assert_eq!(wrapper.protocols.len(), 8)
    }

	#[test]
	fn test_tcp() {
		let packet = [// Ethernet 
					  0xde, 0xf0, 0x12, 0x34, 0x45, 0x67, /* destination */
                      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, /* source */
                      0x08, 0x00, /* ethertype */
					  // Ipv4
					  0x45,           /* ver/ihl */
                      0x11,           /* dscp/ecn */
                      0x00, 0x73,     /* total len */
                      0x01, 0x01,     /* identification */
                      0x41, 0x01,     /* flags/frag offset */
                      0x40,           /* ttl */
                      0x06,           /* proto */
                      0xb6, 0x4e,     /* checksum */
                      0xc0, 0xa8, 0x00, 0x01, /* source ip */
                      0xc0, 0xa8, 0x00, 0xc7, /* dest ip */
					  // Tcp
					  0xc1, 0x67, /* source */
                      0x23, 0x28, /* destination */
                      0x90, 0x37, 0xd2, 0xb8, /* seq */
                      0x94, 0x4b, 0xb2, 0x76, /* ack */
                      0x80, 0x18, 0x0f, 0xaf, /* length, flags, win */
                      0xc0, 0x31, /* checksum */
                      0x00, 0x00,  /* urg ptr */
                      0x01, 0x01, /* options: nop */
                      0x08, 0x0a, 0x2c, 0x57,
                      0xcd, 0xa5, 0x02, 0xa0,
                      0x41, 0x92, /* timestamp */
                      0x74, 0x65, 0x73, 0x74 /* "test" */
                      ];
			let ethernet = EthernetPacket::new(&packet).unwrap();
			let wrapper = Wrapper::decap(&ethernet, 3);
			

			assert_eq!(wrapper.protocols.len(), 3)
	}
}
