use crate::util::Ipv6AddrC;
use socket2::{MaybeUninitSlice, Socket};
use std::fmt::Formatter;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{fmt, io, mem};
use tokio::io::unix::AsyncFd;

macro_rules! sock_filters {
    ( $( { $code:expr, $jt:expr, $jf:expr, $k:expr } ),* ) => {
        [
            $(
                libc::sock_filter { code: $code, jt: $jt, jf: $jf, k: $k, }
            ),*
        ]
    };
}

pub fn apply_bpf_filter(sock: &Socket, port: u16, v4: bool) -> io::Result<()> {
	use libc::__u32;
	// ldxb	4*([0]&0xf)
	// ldh	[x + 2]
	// jne	#0xca6e , bad
	// ldh	[x + 4]
	// jlt	#12	, good
	// ld	[x + 8]
	// st	M[0]
	// and	#0xffffff
	// jne	#0	,good
	// ld	M[0]
	// and	#0xff000000
	// rsh	#24
	// jgt	#4	, good, bad
	// good: ret #0x4000
	// bad: ret #0
	let v4_filter = sock_filters![
		{ 0xb1,  0,  0, 0000000000 },
		{ 0x48,  0,  0, 0x00000002 },
		{ 0x15,  0, 11, port as __u32 },
		{ 0x48,  0,  0, 0x00000004 },
		{ 0x35,  0,  8, 0x0000000c },
		{ 0x40,  0,  0, 0x00000008 },
		{ 0x02,  0,  0, 0000000000 },
		{ 0x54,  0,  0, 0x00ffffff },
		{ 0x15,  0,  4, 0000000000 },
		{ 0x60,  0,  0, 0000000000 },
		{ 0x54,  0,  0, 0xff000000 },
		{ 0x74,  0,  0, 0x00000018 },
		{ 0x25,  0,  1, 0x00000004 },
		{ 0x06,  0,  0, 0x00004000 },
		{ 0x06,  0,  0, 0000000000 }
	];
	// ldb	[6]
	// ldx	#40
	// jeq	#17	,udp
	// # unroll 0
	// ldb	[x + 0]
	// st	M[0]
	// ldb	[x + 1]
	// add	x
	// ld	M[0]
	// jeq	#17	,udp, bad
	//
	// udp: ldh	[x + 2]
	// jne	#0xca6e , bad
	// ldh	[x + 4]
	// jlt	#12	, good
	// ld	[x + 8]
	// st	M[0]
	// and	#0xffffff
	// jne	#0	,good
	// ld	M[0]
	// and	#0xff000000
	// rsh	#24
	// jgt	#4	, good, bad
	// good: ret #0x4000
	// bad: ret #0
	let v6_filter = sock_filters![
		{ 0x30,  0,  0, 0x00000006 },
		{ 0x01,  0,  0, 0x00000028 },
		{ 0x15,  6,  0, 0x00000011 },
		{ 0x50,  0,  0, 0000000000 },
		{ 0x02,  0,  0, 0000000000 },
		{ 0x50,  0,  0, 0x00000001 },
		{ 0x0c,  0,  0, 0000000000 },
		{ 0x60,  0,  0, 0000000000 },
		{ 0x15,  0, 13, 0x00000011 },
		{ 0x48,  0,  0, 0x00000002 },
		{ 0x15,  0, 11, port as __u32 },
		{ 0x48,  0,  0, 0x00000004 },
		{ 0x35,  0,  8, 0x0000000c },
		{ 0x40,  0,  0, 0x00000008 },
		{ 0x02,  0,  0, 0000000000 },
		{ 0x54,  0,  0, 0x00ffffff },
		{ 0x15,  0,  4, 0000000000 },
		{ 0x60,  0,  0, 0000000000 },
		{ 0x54,  0,  0, 0xff000000 },
		{ 0x74,  0,  0, 0x00000018 },
		{ 0x25,  0,  1, 0x00000004 },
		{ 0x06,  0,  0, 0x00004000 },
		{ 0x06,  0,  0, 0000000000 }
	];
	if v4 {
		sock.attach_filter(&v4_filter)
	} else {
		sock.attach_filter(&v6_filter)
	}
}

pub trait AsByteSlice {
	fn as_slice(&self) -> &[u8]
	where Self: Sized
	{
		unsafe {
			core::slice::from_raw_parts(
				(self as *const Self) as *const u8,
				size_of::<Self>(),
			)
		}
	}
	fn as_mut_slice(&mut self) -> &mut [u8] 
	where Self: Sized {
		unsafe {
			core::slice::from_raw_parts_mut(
				(self as *mut Self) as *mut u8,
				size_of::<Self>()
			)
		}
	}
	fn as_u16_slice(&self) -> &[u16]
	where Self: Sized
	{
		unsafe {
			core::slice::from_raw_parts(
				(self as *const Self) as *const u16,
				size_of::<Self>() / 2,
			)
		}
	}
}

#[repr(C)]
#[derive(Debug)]
pub struct UdpHdr {
	sport: u16,
	dport: u16,
	len: u16,
	chksum: u16
}
impl UdpHdr {
	pub fn new(sport: u16, dport: u16, len: u16, chksum: u16) -> Self {
		Self {
			sport: sport.to_be(),
			dport: dport.to_be(),
			len: len.to_be(),
			chksum: chksum.to_be()
		}
	}
	pub fn from_buffer(raddr: &SocketAddr, saddr: &SocketAddr, buf: &[u8]) -> Self {

		match (raddr, saddr) {
			(SocketAddr::V4(raddr4), SocketAddr::V4(saddr4)) => {
				let mut chksum = 0u32;

				chksum += saddr4.ip().to_bits() & 0xffff;
				chksum += saddr4.ip().to_bits()>> 16;
				chksum += raddr4.ip().to_bits() & 0xffff;
				chksum += raddr4.ip().to_bits()>> 16;
				chksum += 17;
				chksum += (buf.len() as u16 + size_of::<Self>() as u16) as u32;
				chksum += saddr4.port() as u32;
				chksum += raddr4.port() as u32;
				chksum += (buf.len() + size_of::<Self>()) as u32;
				for d in (0..buf.len() - (buf.len() & 1)).step_by(2) {
					chksum += u16::from_be_bytes([buf[d], buf[d + 1]]) as u32;
				}
				
				if (buf.len() & 1) != 0 {
					chksum += buf[buf.len() - 1] as u32;
				}

				chksum = (chksum & 0xffff) + (chksum >> 16);
				chksum = (chksum & 0xffff) + (chksum >> 16);
				Self {
					sport: saddr4.port().to_be(),
					dport: raddr4.port().to_be(),
					len: (buf.len() as u16 + 8u16).to_be(),
					chksum: !(chksum as u16).to_be(),
				}
			}
			(SocketAddr::V6(raddr6), SocketAddr::V6(saddr6)) => {
				let mut chksum = 0u32;
				for u in saddr6.ip().segments() {
					chksum += u.to_be() as u32;
				}
				for u in raddr6.ip().segments() {
					chksum += u.to_be() as u32;
				}
				chksum += ((buf.len() + size_of::<Self>()) as u16) as u32;
				chksum += 17;
				chksum += saddr6.port() as u32;
				chksum += raddr6.port() as u32;

				for i in (0..buf.len() - (buf.len() & 1)).step_by(2) {
					chksum += u16::from_le_bytes([buf[i], buf[i + 1]]) as u32;
				}
				
				if (buf.len() & 1) != 0 {
					chksum += buf[buf.len() - 1] as u32;
				}
				
				chksum = (chksum & 0xffff) + (chksum >> 16);
				chksum = (chksum & 0xffff) + (chksum >> 16);
				Self {
					sport: raddr6.port().to_be(),
					dport: raddr6.port().to_be(),
					len: (buf.len() as u16 + 8u16).to_be(),
					chksum: !(chksum as u16).to_be(),
				}
			},
			(_,_) => {
				panic!("no support as family not equal")
			}
		}

	}
	pub fn sport(&self) -> u16 {
		self.sport.to_be()
	}
	pub fn dport(&self) -> u16 {
		self.dport.to_be()
	}
	pub fn len(&self) -> u16 {
		self.len.to_be()
	}
	pub fn chksum(&self) -> u16 {
		self.chksum.to_le()
	}
}
impl AsByteSlice for UdpHdr {}

impl fmt::Display for UdpHdr {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "{}=>{} len:{} chksum: {:02x}", self.sport(), self.dport(), self.len(), self.chksum())
	}
}

pub struct AsyncSocket {
	inner: AsyncFd<socket2::Socket>,
}

impl AsyncSocket {
	pub fn new(sock: socket2::Socket) -> io::Result<Self> {
		sock.set_nonblocking(true)?;
		let afd = AsyncFd::new(sock)?;
		Ok(Self { inner: afd })
	}
	pub async fn recv_from(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, socket2::SockAddr)> {
		loop {
			let mut guard = self.inner.readable().await?;
			match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
				Ok(result) => return result,
				Err(_) => continue,
			}
		}
	}
	pub async fn recv_from_vectored(&self, bufs: &mut [MaybeUninitSlice<'_>],) -> std::io::Result<(usize, socket2::RecvFlags, socket2::SockAddr)> {
		loop {
			let mut guard = self.inner.readable().await?;
			match guard.try_io(|inner| inner.get_ref().recv_from_vectored(bufs)) {
				Ok(result) => return result,
				Err(_) => continue,
			}
		}
	}
	pub async fn send_to(&self, buf: &[u8], addr: &socket2::SockAddr) -> io::Result<usize> {
		loop {
			let mut guard = self.inner.writable().await?;
			match guard.try_io(|inner| inner.get_ref().send_to(buf, addr)) {
				Ok(result) => return result,
				Err(_) => continue,
			}
		}
	}
	pub async fn send_to_vectored(&self, bufs: &[IoSlice<'_>], addr: &socket2::SockAddr) -> io::Result<usize> {
		loop {
			let mut guard = self.inner.writable().await?;
			match guard.try_io(|inner| inner.get_ref().send_to_vectored(bufs, addr)) {
				Ok(result) => return result,
				Err(_) => continue,
			}
		}
	}
}
pub struct RawUdpSocket {
	ipv4: bool,
	inner: AsyncSocket
}

impl RawUdpSocket {
	pub fn new(sock: socket2::Socket, ipv4: bool) -> io::Result<Self> {

		let afd = AsyncSocket::new(sock)?;
		Ok(Self {
			ipv4,
			inner: afd
		})
	}
	pub async fn send_to(&self, buf: &[u8], raddr: SocketAddr, saddr: SocketAddr) -> io::Result<usize> {
		// trace!("raw send_to {} => {} len:{}", saddr, raddr, buf.len());
		let sock_addr = socket2::SockAddr::from(raddr);

		let udp_hdr = UdpHdr::from_buffer(&raddr, &saddr, buf);
		let iovs = [IoSlice::new(udp_hdr.as_slice()), IoSlice::new(buf)];

		self.inner.send_to_vectored(&iovs, &sock_addr).await
	}
	pub async fn recv_from4(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
		
		let mut ipudp:[MaybeUninit<u8>; 8 + 20] = [MaybeUninit::uninit(); 8 + 20];
		let buf_ = unsafe { mem::transmute::<_, &mut [MaybeUninit<u8>]>(buf) };
		let mut iovs = [MaybeUninitSlice::new(ipudp.as_mut_slice()), MaybeUninitSlice::new(buf_)];
		let (size, _, _) = self.inner.recv_from_vectored(&mut iovs).await?;
		if size < size_of_val(&ipudp) {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "udp packet too short"));
		}

		let hdr_buf = unsafe { mem::transmute::<_, &[u8]>(&ipudp[0..]) };
		let raddr = SocketAddrV4::new(
			Ipv4Addr::new(hdr_buf[12], hdr_buf[13], hdr_buf[14], hdr_buf[15]),
			u16::from_be_bytes([hdr_buf[20], hdr_buf[21]]));
		let laddr = SocketAddrV4::new(
			Ipv4Addr::new(hdr_buf[16], hdr_buf[17], hdr_buf[18], hdr_buf[19]),
			u16::from_be_bytes([hdr_buf[22], hdr_buf[23]]));

		Ok((size - 28, laddr.into(), raddr.into()))
	}
	pub async fn recv_from6(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {

		let mut ipudp:[MaybeUninit<u8>; 8 + 40] = [MaybeUninit::uninit(); 8 + 40];
		let buf_ = unsafe { mem::transmute::<_, &mut [MaybeUninit<u8>]>(buf) };
		let mut iovs = [MaybeUninitSlice::new(ipudp.as_mut_slice()), MaybeUninitSlice::new(buf_)];
		let (size, _, _) = self.inner.recv_from_vectored(&mut iovs).await?;
		if size < size_of_val(&ipudp) {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "udp packet too short"));
		}
		let hdr_buf = unsafe { mem::transmute::<_, &[u8]>(&ipudp[0..]) };
		let raddr = SocketAddrV6::new(Ipv6AddrC::from(&hdr_buf[8..24]).into(), 
									  u16::from_be_bytes([hdr_buf[40], hdr_buf[41]]), 0, 0);
		let laddr = SocketAddrV6::new(Ipv6AddrC::from(&hdr_buf[24..40]).into(),
									  u16::from_be_bytes([hdr_buf[42], hdr_buf[43]]), 0, 0);
		Ok((size - 48, laddr.into(), raddr.into()))
	}
	pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
		if self.ipv4 {
			let (len, _, raddr) = self.recv_from4(buf).await?;
			Ok((len, raddr))
		}else {
			let (len, _, raddr) = self.recv_from6(buf).await?;
			Ok((len, raddr))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::Rng;
	pub struct PHdr {
		pub saddr: Ipv4Addr,
		pub daddr: Ipv4Addr,
		pub rsv: u8,
		pub proto: u8,
		pub len: u16
	}
	impl AsByteSlice for PHdr {}

	#[test]
	fn test_udp_cksum() {
		let rip = Ipv4Addr::new(127, 0, 0, 1);
		let lip = Ipv4Addr::new(127, 0, 0, 2);
		let raddr = SocketAddrV4::new(rip, 3478).into();
		let laddr = SocketAddrV4::new(lip, 51821).into();

		let buffer = [];
		let udp = UdpHdr::from_buffer(&raddr, &laddr, &buffer);
		println!("{}", udp);
		let phdr = PHdr {
			saddr: rip,
			daddr: lip,
			rsv: 0,
			proto: 17,
			len: (8u16 + buffer.len() as u16).to_be(),
		};
		let mut csum = 0u32;
		for d in phdr.as_u16_slice() {
			csum += (*d) as u32;
		}
		for d in udp.as_u16_slice() {
			csum += (*d) as u32;
		}
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		assert_eq!(!(csum as u16), 0);
	}
	#[test]
	fn test_udp_cksum_buffer() {
		let rip = Ipv4Addr::new(127, 0, 0, 1);
		let lip = Ipv4Addr::new(127, 0, 0, 2);
		let raddr = SocketAddrV4::new(rip, 3478).into();
		let laddr = SocketAddrV4::new(lip, 51821).into();

		let buffer = [0;9];
		let udp = UdpHdr::from_buffer(&raddr, &laddr, &buffer);
		println!("{}", udp);
		let phdr = PHdr {
			saddr: rip,
			daddr: lip,
			rsv: 0,
			proto: 17,
			len: (8u16 + buffer.len() as u16).to_be(),
		};
		let mut csum = 0u32;
		for d in phdr.as_u16_slice() {
			csum += (*d) as u32;
		}
		for d in udp.as_u16_slice() {
			csum += (*d) as u32;
		}
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		assert_eq!(!(csum as u16), 0);
	}

	#[test]
	fn test_udp_cksum_with_buffer() {
		let rip = Ipv4Addr::new(127, 0, 0, 1);
		let lip = Ipv4Addr::new(127, 0, 0, 1);
		let raddr = SocketAddrV4::new(rip, 3478).into();
		let laddr = SocketAddrV4::new(lip, 51820).into();

		let buffer = rand::thread_rng().gen::<[u8; 32]>();
		let udp = UdpHdr::from_buffer(&raddr, &laddr, &buffer);

		let phdr = PHdr {
			saddr: rip,
			daddr: lip,
			rsv: 0,
			proto: 17,
			len: (8u16 + buffer.len() as u16).to_be(),
		};
		let mut csum = 0u32;
		for d in phdr.as_u16_slice() {
			csum += (*d) as u32;
		}
		for d in udp.as_u16_slice() {
			csum += (*d) as u32;
		}
		println!("{:?}", unsafe {mem::transmute::<[u8;32], [u16;16]>(buffer)});
		for d in unsafe {mem::transmute::<[u8;32], [u16;16]>(buffer)} {
			csum += d as u32;
		}
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		assert_eq!(!(csum as u16), 0);
	}
}