use crate::config::InterfacePolicy;
use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

pub const SOCKETADDRV4_UNSPECIFIED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
pub const SOCKETADDRV6_UNSPECIFIED: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
pub const IPADDRV4_UNSPECIFIED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const IPADDRV6_UNSPECIFIED: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// Generates a new key pair (public key and secret key).
///
/// # Returns
///
/// A tuple containing the public key and secret key as base64-encoded strings.
///
/// # Example
///
/// ```rust
/// use wgmqc::util::new_key_pair;
/// let (public_key, secret_key) = new_key_pair();
/// println!("Public Key: {}", public_key);
/// println!("Secret Key: {}", secret_key);
/// ```
pub fn new_key_pair() -> (String, String) {
	let alice_secret = StaticSecret::random();
	let alice_public = PublicKey::from(&alice_secret);
	(
		base64::prelude::BASE64_STANDARD.encode(alice_public.to_bytes()),
		base64::prelude::BASE64_STANDARD.encode(alice_secret.to_bytes()),
	)
}

pub fn base64_to_hex(s: &str) -> Option<String> {
	let decoded = match base64::prelude::BASE64_STANDARD.decode(&s) {
		Ok(d) => d,
		Err(_) => return None,
	};
	let mut hex = String::with_capacity(decoded.len() * 2);
	for b in decoded.iter() {
		hex.push_str(&format!("{:02x?}", b));
	}
	Some(hex)
}

pub(crate) fn keystr_to_array(s: &str) -> Option<[u8; 32]> {
	let pri_key = base64::prelude::BASE64_STANDARD.decode(s);
	match pri_key {
		Ok(p) => {
			if p.len() != 32 {
				return None;
			}
			let mut pp: [u8; 32] = [0; 32];
			pp.copy_from_slice(&p);
			Some(pp)
		}
		Err(_) => None,
	}
}
pub fn safe_write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<(), std::io::Error> {
	let pb = PathBuf::from(path.as_ref());
	let raw_filename = pb.file_name().unwrap();
	let tmp_filename = format!(".{}.tmp", raw_filename.to_str().unwrap());
	let mut tmp_pb = pb.clone();
	tmp_pb.set_file_name(tmp_filename);

	std::fs::write(tmp_pb.as_path(), contents)?;
	std::fs::rename(tmp_pb.as_path(), pb.as_path())?;

	Ok(())
}

pub fn filter_avail_interface(policy: &InterfacePolicy) -> Vec<netdev::Interface> {
	if policy.interface.is_some() {
		let intfname = policy.interface.clone().unwrap();
		let intf: Vec<netdev::Interface> = netdev::get_interfaces()
			.into_iter()
			.filter(|x| x.name.eq(&intfname))
			.collect();
		if intf.is_empty() {
			return vec![];
		}

		return intf;
	}
	if policy.use_def_route() {
		if let Ok(i) = netdev::get_default_interface() {
			return vec![i];
		}
	}

	let mut allow = None;
	let mut block = None;

	if let Some(allow_reg) = policy.allow_interface_regex.clone() {
		if let Ok(reg) = regex::Regex::new(&allow_reg) {
			allow = Some(reg)
		}
	}
	if let Some(block_reg) = policy.block_interface_regex.clone() {
		if let Ok(reg) = regex::Regex::new(&block_reg) {
			block = Some(reg)
		}
	}

	netdev::get_interfaces()
		.into_iter()
		.filter(|i| {
			if let Some(allow_) = &allow {
				allow_.is_match(i.name.as_str())
			} else {
				true
			}
		})
		.filter(|i| {
			if let Some(block_) = &block {
				!block_.is_match(i.name.as_str())
			} else {
				true
			}
		})
		.filter(|i| {
			// skip macos feth and utun interface
			#[cfg(target_os = "macos")]
			if i.name.starts_with("feth") || i.name.starts_with("utun") {
				return false;
			}
			// skip docker bridge
			if i.name.starts_with("docker0") ||
				// skip virtual interfaces
				i.name.starts_with("virbr") ||
				// skip zerotier interface
				i.name.starts_with("zt") ||
				i.name.starts_with("tun") ||
				i.name.starts_with("tap") ||
				i.name.starts_with("feth") ||
				i.is_loopback()
			{
				false
			} else {
				true
			}
		})
		.collect()
}

pub struct Ipv6AddrC(pub Ipv6Addr);
impl From<Ipv6Addr> for Ipv6AddrC {
	fn from(value: Ipv6Addr) -> Self {
		Self { 0: value }
	}
}
impl Ipv6AddrC {
	#[inline]
	pub const fn segments(&self) -> [u16; 8] {
		self.0.segments()
	}
	#[inline]
	pub const fn is_unspecified(&self) -> bool {
		self.0.is_unspecified()
	}
	#[inline]
	pub const fn is_loopback(&self) -> bool {
		self.0.is_loopback()
	}
	#[inline]
	pub const fn is_unicast_link_local(&self) -> bool {
		(self.segments()[0] & 0xffc0) == 0xfe80
	}
	#[inline]
	pub const fn is_documentation(&self) -> bool {
		(self.segments()[0] == 0x2001) && (self.segments()[1] == 0xdb8)
	}
	#[inline]
	pub const fn is_benchmarking(&self) -> bool {
		(self.segments()[0] == 0x2001) && (self.segments()[1] == 0x2) && (self.segments()[2] == 0)
	}
	#[inline]
	pub const fn is_unicast(&self) -> bool {
		!self.is_multicast()
	}
	#[inline]
	pub const fn is_multicast(&self) -> bool {
		(self.segments()[0] & 0xff00) == 0xff00
	}
	#[inline]
	pub const fn is_unicast_global(&self) -> bool {
		self.is_unicast()
			&& !self.is_loopback()
			&& !self.is_unicast_link_local()
			&& !self.is_unique_local()
			&& !self.is_unspecified()
			&& !self.is_documentation()
			&& !self.is_benchmarking()
	}
	#[inline]
	pub const fn is_unique_local(&self) -> bool {
		(self.segments()[0] & 0xfe00) == 0xfc00
	}
	#[inline]
	pub const fn octets(&self) -> [u8; 16] {
		self.0.octets()
	}

	pub const fn is_global(&self) -> bool {
		!(self.is_unspecified()
			|| self.is_loopback()
			// IPv4-mapped Address (`::ffff:0:0/96`)
			|| matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
			// IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
			|| matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
			// Discard-Only Address Block (`100::/64`)
			|| matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
			// IETF Protocol Assignments (`2001::/23`)
			|| (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
			&& !(
			// Port Control Protocol Anycast (`2001:1::1`)
			u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
				// Traversal Using Relays around NAT Anycast (`2001:1::2`)
				|| u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
				// AMT (`2001:3::/32`)
				|| matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
				// AS112-v6 (`2001:4:112::/48`)
				|| matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
				// ORCHIDv2 (`2001:20::/28`)
				// Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
				|| matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
		))
			// 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
			// IANA says N/A.
			|| matches!(self.segments(), [0x2002, _, _, _, _, _, _, _])
			|| self.is_documentation()
			|| self.is_unique_local()
			|| self.is_unicast_link_local())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_new_key_pair() {
		let (public_key, secret_key) = new_key_pair();
		assert!(!public_key.is_empty() && !secret_key.is_empty());
		assert_eq!(public_key.len(), 44);
		assert_eq!(secret_key.len(), 44);
	}
	#[test]
	fn test_base64_to_hex() {
		let h = base64_to_hex("n+pcrycRUuu3V50TWrexOj/xvnAdIkRq0RHo/uFq/Dk=");
		assert!(h.is_some());
		let h = base64_to_hex("n+pcrycRUuu3V50TWrexOj/xvnAdIkRq0RHo/uFq/Dk");
		assert!(h.is_none());
	}
	#[test]
	fn filter_intf_test() {
		let policy = InterfacePolicy::default();

		assert_ne!(filter_avail_interface(&policy).len(), 0);
	}
	#[test]
	fn test_ipnet_format() {
		let ip = ipnet::IpNet::default();
		let s = serde_yaml::to_string(&ip).unwrap();
		println!("{}", s);
	}
}
