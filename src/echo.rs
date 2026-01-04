use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace};
use crate::raw;
use crate::raw::RawUdpSocket;
use crate::util::{IPADDRV4_UNSPECIFIED, IPADDRV6_UNSPECIFIED};

pub(crate) struct EchoServer {
	enable_udp: bool,
	enable_tcp: bool,
	udp_socket: Option<RawUdpSocket>,
	udp_socket6: Option<RawUdpSocket>,
	tcp_listener: Option<TcpListener>,
	tcp_listener6: Option<TcpListener>,
}

fn new_ipv6_raw_socket(addr: SocketAddr) -> Result<RawUdpSocket, io::Error> {
	let socket = socket2::Socket::new(
		socket2::Domain::IPV6,
		socket2::Type::RAW,
		Some(socket2::Protocol::UDP),
	).expect("cannot create raw socket");

	// socket.set_only_v6(true).expect("cannot set only ipv6");
	raw::apply_bpf_filter(&socket, addr.port(), false).expect("cannot apply raw socket");

	RawUdpSocket::new(socket, false)
}
fn new_ipv4_raw_socket(addr: SocketAddr) -> Result<RawUdpSocket, io::Error> {
	let socket = socket2::Socket::new(
		socket2::Domain::IPV4,
		socket2::Type::RAW,
		Some(socket2::Protocol::UDP),
	)?;
	raw::apply_bpf_filter(&socket, addr.port(), true)?;

	RawUdpSocket::new(socket, true)
}

async fn tcp_steam_echo(mut stream: tokio::net::TcpStream, cancellation_token: CancellationToken) {
	loop {
		let mut read = [0; 1024];
		tokio::select! {
			recv = stream.read(&mut read) => {
				match recv {
				Ok(n) => {
					if n == 0 {
						break; // connection was closed
					}
					let _ = stream.write_all(&read[0..n]).await;
				}
				Err(_) => break,
				}
			},
			_ = cancellation_token.cancelled() => break,
		}
	}
}

impl EchoServer {
	pub(crate) async fn new(udp_port: u16, tcp_port: u16) -> Result<Self, io::Error> {
		let (udp4, udp6) = if udp_port != 0 {
			(
				Some(new_ipv4_raw_socket(SocketAddr::new(IPADDRV4_UNSPECIFIED, udp_port)).expect("cannot bind4 udp")),
				Some(new_ipv6_raw_socket(SocketAddr::new(IPADDRV6_UNSPECIFIED, udp_port)).expect("cannot bind6 udp")),
			)
		} else {
			(None, None)
		};
		let (tcp4, tcp6) = if tcp_port != 0 {
			(
				Some(TcpListener::bind(SocketAddr::new(IPADDRV4_UNSPECIFIED, tcp_port)).await?),
				Some(TcpListener::bind(SocketAddr::new(IPADDRV6_UNSPECIFIED, tcp_port)).await?),
			)
		} else {
			(None, None)
		};

		Ok(Self {
			enable_udp: udp_port != 0,
			enable_tcp: tcp_port != 0,
			udp_socket: udp4,
			udp_socket6: udp6,
			tcp_listener: tcp4,
			tcp_listener6: tcp6,
		})
	}
	pub(crate) fn get_udp_sock(&self) -> &Option<RawUdpSocket> {
		&self.udp_socket
	}
	pub(crate) async fn start_udp_echo(
		&self,
		cancellation_token: &CancellationToken,
		buf: &mut Box<[u8; 16384]>,
	) -> Result<(), io::Error> {
		// debug!("Starting udp echo server");
		if !self.enable_udp {
			_ = cancellation_token.cancelled().await;
			return Ok(());
		}
		let udp_sock = &self.udp_socket;
		let udp_sock6 = &self.udp_socket6;
		let len = buf.len();
		let (buf4, buf6) = buf.split_at_mut(len / 2);
		tokio::select! {
		udp4_recv = udp_sock.as_ref().unwrap().recv_from4(buf4) => {
			match udp4_recv {
				Err(e) => {
					error!("udp recv error {}", e);
				},
				Ok((p, dst, src)) => {
					trace!("udp recv from {}:{}", p, src);
					if p > 0 {
						let _ = udp_sock.as_ref().unwrap().send_to(&buf4[0..p], src, dst).await;
					}
				}
			}
		},
		udp6_recv = udp_sock6.as_ref().unwrap().recv_from6(buf6) => {
			match udp6_recv {
				Err(e) => {
					error!("udp recv error {}", e);
				},
				Ok((p, dst, src)) => {
					trace!("udp recv from {}:{}", p, src);
					if p > 0 {
						let _ = udp_sock.as_ref().unwrap().send_to(&buf6[0..p], src, dst).await;
					}
				}
			}
		},
			_ = cancellation_token.cancelled() => {},
		}
		Ok(())
	}
	pub(crate) async fn start_tcp_echo(&self, cancellation_token: &CancellationToken) -> Result<(), io::Error> {
		if !self.enable_tcp {
			cancellation_token.cancelled().await;
			return Ok(());
		}
		loop {
			tokio::select! {
				Ok(x4) = self.tcp_listener.as_ref().unwrap().accept() => {
					let ( stream, addr) = x4;
					debug!("tcp connected from {}", addr);
					tokio::spawn(tcp_steam_echo(stream, cancellation_token.clone()));
				},
				Ok(x6) = self.tcp_listener6.as_ref().unwrap().accept() => {
					let ( stream, addr) = x6;
					debug!("tcp connected from {}", addr);
					tokio::spawn(tcp_steam_echo(stream, cancellation_token.clone()));
				}
				_ = cancellation_token.cancelled() => break,
			}
		}
		Ok(())
	}
}