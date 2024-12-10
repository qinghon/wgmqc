use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IceAddr {
	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub lan: Vec<SocketAddr>,
	// global ipv6
	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub ipv6: Vec<SocketAddr>,

	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub stun: Vec<SocketAddr>,

	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub port_map: Vec<SocketAddr>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub statics: Vec<SocketAddr>,

	#[serde(default)]
	pub support_udp: bool,
}
/*
impl IceAddr {
	pub fn is_empty(&self) -> bool {
		self.lan.is_empty() &&
			self.ipv6.is_empty() &&
			self.stun.is_empty() &&
			self.port_map.is_empty() &&
			self.statics.is_empty()
	}
}*/
