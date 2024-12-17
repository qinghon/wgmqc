use crate::config;
use log::{debug, error, info};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use stunclient::{Error, StunClient};
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

async fn stun_get_external_addr(udp: &UdpSocket, raddr: String) -> Result<SocketAddr, io::Error> {
	info!("get raddr {}", raddr);

	let stun_addr = raddr.to_socket_addrs()?.filter(|x| x.is_ipv4()).next();
	if stun_addr.is_none() {
		return Err(io::Error::new(
			io::ErrorKind::AddrNotAvailable,
			"cannot resolv avail ipv4 addr",
		));
	}
	let stun_addr = stun_addr.unwrap();
	let c = StunClient::new(stun_addr);
	let f = c.query_external_address_async(&udp).await;
	match f {
		Ok(addr) => Ok(addr),
		Err(e) => match e {
			Error::Bytecodec(_) | Error::Stun(_) | Error::NoAddress(_) => {
				Err(io::Error::new(io::ErrorKind::NotFound, "stun server error"))
			}

			Error::Socket(_) => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "local udp error")),
			Error::Timeout(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
			_ => Err(io::Error::new(io::ErrorKind::Unsupported, "unknown")),
		},
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
	use std::net::{IpAddr, Ipv4Addr};

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
