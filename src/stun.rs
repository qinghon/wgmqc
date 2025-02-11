use crate::config;
use crate::raw::RawUdpSocket;
use crate::util::SOCKETADDRV4_UNSPECIFIED;
use anyhow::Error;
use bytecodec::{DecodeExt, EncodeExt};
use log::{debug, error, info};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::time::Duration;
use std::io;
use stun_codec::rfc5389::attributes::{MappedAddress, Software, XorMappedAddress};
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
use stunclient::StunClient;
use tokio::net::UdpSocket;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StunType {
	Public,
	FullCone,
	RestrictedCone,
	PortRestrictedCone,
	Symmetric,
	Blocked,
}

async fn stun_get_external_addr(udp: &UdpSocket, raddr: String) -> Result<SocketAddr, Error> {
	info!("get raddr {}", raddr);

	let stun_addr = raddr.to_socket_addrs()?.filter(|x| x.is_ipv4()).next();
	if stun_addr.is_none() {
		return Err(io::Error::new(
			io::ErrorKind::AddrNotAvailable,
			"cannot resolv avail ipv4 addr",
		).into());
	}
	let stun_addr = stun_addr.unwrap();
	let c = StunClient::new(stun_addr);
	let f = c.query_external_address_async(&udp).await;
	match f {
		Ok(addr) => Ok(addr),
		Err(e) => Err(Error::new(e)),
	}
}

pub async fn stun_do_trans(
	laddr: SocketAddr,
	raddr: Vec<String>,
	udpsock: Option<(&UdpSocket, u16)>,
) -> io::Result<(Vec<SocketAddr>, StunType)> {
	if raddr.is_empty() {
		return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "addr is empty"));
	}
	let real_laddr;
	let sock;
	let udp = if udpsock.is_some() {
		real_laddr = SocketAddr::new(
			udpsock.as_ref().unwrap().0.local_addr()?.ip(),
			udpsock.as_ref().unwrap().1,
		);
		udpsock.unwrap().0
	} else {
		sock = tokio::net::UdpSocket::bind(&laddr).await?;
		real_laddr = sock.local_addr()?;
		&sock
	};

	debug!("stun do trans: {} {:?}", laddr, raddr);

	// let real_laddr = udp.local_addr()?;

	let mut ok_num = 0;
	let mut err_num = 0;
	let total_num = raddr.len();

	let mut public_addrs = vec![];

	for remote in raddr.into_iter() {
		// test1
		match stun_get_external_addr(&udp, remote).await {
			Ok(pubaddr) => {
				info!("pubaddr {}", pubaddr);
				ok_num += 1;
				if pubaddr == real_laddr {
					return Ok((vec![pubaddr], StunType::Public));
				}

				public_addrs.push(pubaddr);
			}
			Err(e) => {
				error!("cannot get stun {}", e);
				err_num += 1;
				if ok_num == 0 && err_num == total_num {
					return Err(io::Error::new(
						io::ErrorKind::AddrNotAvailable,
						"cannot get any stun server",
					));
				}
			}
		}
	}

	match public_addrs.len() {
		0 => {
			return Err(io::Error::new(
				io::ErrorKind::AddrNotAvailable,
				"cannot get any stun server",
			));
		}
		1 => {
			let addr = public_addrs[0];
			if addr.port() == real_laddr.port() {
				return Ok((vec![addr], StunType::FullCone));
			} else {
				return Ok((vec![addr], StunType::RestrictedCone));
			}
		}
		_ => {
			let mut stun_type = StunType::Blocked;
			if public_addrs.iter().all(|&x| x == public_addrs[0]) {
				stun_type = StunType::FullCone;
			}
			let ports: Vec<u16> = public_addrs.iter().map(|x| x.port()).collect();
			if ports.iter().all(|&x| x == ports[0]) {
				stun_type = StunType::FullCone;
			}
			if ports.iter().all(|&x| ports.iter().filter(|&&y| x == y).count() == 1) {
				stun_type = StunType::Symmetric;
			}
			public_addrs.sort();
			public_addrs.dedup();
			if stun_type != StunType::Blocked {
				return Ok((public_addrs, stun_type));
			}
		}
	}

	Ok((vec![], StunType::Blocked))
}


fn decode_address(buf: &[u8]) -> Result<SocketAddr, Error> {
	let mut decoder = MessageDecoder::<Attribute>::new();
	let decoded = decoder
		.decode_from_bytes(buf)?
		.map_err(|e|io::Error::new(io::ErrorKind::InvalidData, e.error().to_owned()))?;

	//eprintln!("Decoded message: {:?}", decoded);

	let external_addr1 = decoded
		.get_attribute::<XorMappedAddress>()
		.map(|x| x.address());
	//let external_addr2 = decoded.get_attribute::<XorMappedAddress2>().map(|x|x.address());
	let external_addr3 = decoded
		.get_attribute::<MappedAddress>()
		.map(|x| x.address());
	let external_addr = external_addr1
		// .or(external_addr2)
		.or(external_addr3);
	let external_addr = external_addr.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))?;

	Ok(external_addr)
}
fn get_binding_request() -> Result<Vec<u8>, Error> {
	use rand::Rng;
	let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

	let mut message: Message<Attribute> = Message::new(
		MessageClass::Request,
		BINDING,
		TransactionId::new(random_bytes),
	);

	
	message.add_attribute(Attribute::Software(
		Software::new("wgmqc".to_owned())?,
	));
	

	// Encodes the message
	let mut encoder = MessageEncoder::new();
	let bytes = encoder
		.encode_into_bytes(message.clone())?;
	Ok(bytes)
}

async fn query_external_address_async_impl(
	udp: &RawUdpSocket,
	stun_server: SocketAddr,
	local_addr: SocketAddr,
) -> Result<SocketAddr, Error> {
	let mut interval = tokio::time::interval(Duration::new(2,0));
	interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

	let rq = get_binding_request()?;
	let mut buf : [u8; 256]= [0;256];

	loop {
		tokio::select! {
                biased; // to make impl simpler
                _t = interval.tick() => {
                    udp.send_to(&rq[..], stun_server, local_addr).await?;
                }
                c = udp.recv_from(&mut buf) => {
                    let (len, from) = c?;
                    if from != stun_server {
                        continue;
                    }
                    let buf = &buf[0..len];
                    let external_addr = decode_address(buf)?;
                    return Ok(external_addr);
                }
            }
	}
}
pub async fn query_external_address_async(
	udp: &RawUdpSocket,
	stun_server: SocketAddr,
	local_addr: SocketAddr,
) -> Result<SocketAddr, Error> {
	let timeout = Duration::new(10,0);
	let ret = tokio::time::timeout(timeout, 
								   query_external_address_async_impl(udp, stun_server, local_addr)
	).await;
	match ret {
		Ok(Ok(x)) => Ok(x),
		Ok(Err(e)) => Err(e),
		Err(_elapsed) => Err(_elapsed)?,
	}
}

async fn stun_get_external_addr_raw(udp: &RawUdpSocket, local_port:u16, raddr: String) -> Result<(SocketAddr, SocketAddr), Error> {
	info!("get raddr {}", raddr);

	let stun_addr = raddr.to_socket_addrs()?.filter(|x| x.is_ipv4()).next();
	if stun_addr.is_none() {
		return Err(io::Error::new(
			io::ErrorKind::AddrNotAvailable,
			"cannot resolv avail ipv4 addr",
		).into());
	}
	let stun_addr = stun_addr.unwrap();
	// get fill local addr
	let prob_udp = UdpSocket::bind(SOCKETADDRV4_UNSPECIFIED).await?;
	prob_udp.connect(stun_addr).await?;
	let mut local_addr = prob_udp.local_addr()?;
	drop(prob_udp);
	
	local_addr.set_port(local_port);
	
	let f = query_external_address_async(&udp, stun_addr, local_addr).await;
	match f {
		Ok(addr) => Ok((local_addr, addr)),
		Err(e) => Err(e.into()),
	}
}

pub async fn stun_do_trans_raw(
	laddr: SocketAddr,
	raddr: Vec<String>,
	udpsock: &RawUdpSocket
) -> io::Result<(Vec<SocketAddr>, StunType)> {
	if raddr.is_empty() {
		return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "addr is empty"));
	}
	let _udp = std::net::UdpSocket::bind(SOCKETADDRV4_UNSPECIFIED)?;
	

	debug!("stun do trans: {} {:?}", laddr, raddr);

	// let real_laddr = udp.local_addr()?;

	let mut ok_num = 0;
	let mut err_num = 0;
	let total_num = raddr.len();

	let mut public_addrs = vec![];

	for remote in raddr.into_iter() {
		// test1
		match stun_get_external_addr_raw(&udpsock, laddr.port(), remote).await {
			Ok((local_addr, pubaddr)) => {
				info!("pubaddr {}", pubaddr);
				ok_num += 1;
				if pubaddr == local_addr {
					return Ok((vec![pubaddr], StunType::Public));
				}

				public_addrs.push(pubaddr);
			}
			Err(e) => {
				error!("cannot get stun {}", e);
				err_num += 1;
				if ok_num == 0 && err_num == total_num {
					return Err(io::Error::new(
						io::ErrorKind::AddrNotAvailable,
						"cannot get any stun server",
					));
				}
			}
		}
	}

	match public_addrs.len() {
		0 => {
			return Err(io::Error::new(
				io::ErrorKind::AddrNotAvailable,
				"cannot get any stun server",
			));
		}
		1 => {
			let addr = public_addrs[0];
			if addr.port() == laddr.port() {
				return Ok((vec![addr], StunType::FullCone));
			} else {
				return Ok((vec![addr], StunType::RestrictedCone));
			}
		}
		_ => {
			let mut stun_type = StunType::Blocked;
			if public_addrs.iter().all(|&x| x == public_addrs[0]) {
				stun_type = StunType::FullCone;
			}
			let ports: Vec<u16> = public_addrs.iter().map(|x| x.port()).collect();
			if ports.iter().all(|&x| x == ports[0]) {
				stun_type = StunType::FullCone;
			}
			if ports.iter().all(|&x| ports.iter().filter(|&&y| x == y).count() == 1) {
				stun_type = StunType::Symmetric;
			}
			public_addrs.sort();
			public_addrs.dedup();
			if stun_type != StunType::Blocked {
				return Ok((public_addrs, stun_type));
			}
		}
	}

	Ok((vec![], StunType::Blocked))
}

pub fn do_stun_test(port: Option<u16>, stun_server: Option<Vec<String>>) {
	tokio::runtime::Builder::new_current_thread()
		.enable_io()
		.enable_time()
		.worker_threads(1)
		.build()
		.unwrap()
		.block_on(async move {
			let raddr = stun_server.unwrap_or(config::DEFAULT_PUB_STUN_SERVERS.iter().map(|x| x.to_string()).collect());
			let laddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port.unwrap_or(0)));
			println!("pub addr {:?} ", stun_do_trans(laddr, raddr, None).await.unwrap());
		});
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util;

	#[tokio::test]
	async fn test_stun() {
		let env = env_logger::Env::default()
			.filter_or("WG_LOG_LEVEL", "info")
			.write_style_or("WG_LOG_STYLE", "SYSTEMD");
		env_logger::init_from_env(env);

		let res = stun_do_trans(
			util::SOCKETADDRV4_UNSPECIFIED,
			vec![
				"stun1.l.google.com:19302".to_string(),
				"stun.miwifi.com:3478".to_string(),
				"stun.yy.com:3478".to_string(),
			],
			None,
		)
		.await;
		assert!(res.is_ok());
		println!("{:?}", res.unwrap())
	}
}
