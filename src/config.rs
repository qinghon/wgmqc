use crate::util;
use base64::Engine;
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::string::ToString;
use std::{error, fs, io};
use x25519_dalek::{PublicKey, StaticSecret};

pub const DEFAULT_WG_PORT: u16 = 51820;
const DEFAULT_PUBIP_DISCOVERY: [&str; 3] = ["http://ifcfg.cn", "http://ip.3322.net", "https://ip.sb"];
pub const DEFAULT_PUB_STUN_SERVERS: [&str; 4] = [
	"stun.chat.bilibili.com:3478",
	"stun.hot-chilli.net:3478",
	"stun1.l.google.com:19302",
	"stun.miwifi.com:3478",
];

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WgConfig {
	#[serde(rename = "wg")]
	pub wg: Wg,

	#[serde(rename = "discovery")]
	pub discovery: Discovery,

	#[serde(rename = "network")]
	pub network: Network,

	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "status")]
	pub status: Option<Status>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Discovery {
	/// local tcp echo port, for port detection
	pub port: u16,

	/// discovery interval, default 120 sec
	#[serde(skip_serializing_if = "Option::is_none")]
	pub interval: Option<u64>,

	/// stun server list, some free of internet
	#[serde(rename = "stuns")]
	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub stuns: Vec<String>,

	/// discovery public ip server list, some free of internet
	#[serde(rename = "pubip")]
	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub pubip: Vec<Pubip>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub passive: Option<bool>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Pubip {
	#[serde(rename = "url")]
	pub url: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "regex")]
	pub regex: Option<String>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InterfacePolicy {
	/// priority more than `block` or `allow`
	/// if `interface` set, ignore `allow` and `block`
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "interface")]
	pub interface: Option<String>,

	/// `block` has a higher priority than `allow`
	/// system interface filter pipeline
	/// <all intf>
	/// <allow filter>
	/// <block filter>
	/// <inner filter>
	/// if no interface available, disable this network

	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "block_interface_regex")]
	pub block_interface_regex: Option<String>,

	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "allow_interface_regex")]
	pub allow_interface_regex: Option<String>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Network {
	#[serde(rename = "id")]
	pub id: String,

	pub name: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "desc")]
	pub desc: Option<String>,

	#[serde(skip_serializing_if = "Option::is_none")]
	/// send internal ip, default true
	pub send_internal: Option<bool>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub interface_policy: Option<InterfacePolicy>,

	#[serde(rename = "broker")]
	pub broker: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub mq_user: Option<String>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub mq_password: Option<String>,

	#[serde(rename = "broker_admin_pubkey")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub broker_admin_pubkey: Option<String>,

	#[serde(rename = "broker_admin_prikey")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub broker_admin_prikey: Option<String>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub allow_policy: Option<AllowPolicy>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub update_interval: Option<usize>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub deny: Option<Vec<String>>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
pub enum AllowPolicy {
	Public,
	Private,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Status {
	#[serde(rename = "peers")]
	#[serde(skip_serializing_if = "Vec::is_empty")]
	#[serde(default)]
	pub peers: Vec<Peer>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Peer {
	#[serde(rename = "key")]
	pub key: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "name")]
	pub name: Option<String>,

	// 最后使用的地址
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(rename = "endpoint")]
	pub endpoint: Option<SocketAddr>,

	#[serde(rename = "allow_ips")]
	pub allow_ips: Vec<ipnet::IpNet>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Wg {
	#[serde(rename = "name")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub name: Option<String>,

	#[serde(rename = "public")]
	pub public: String,

	#[serde(rename = "private")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub private: Option<String>,

	#[serde(rename = "port")]
	pub port: u16,

	#[serde(rename = "ip")]
	pub ip: Vec<ipnet::IpNet>,
	// #[serde(skip_serializing_if = "Option::is_none")]
	// #[serde(rename = "sign_data")]
	// sign_data: Option<Vec<u8>>,
}

impl WgConfig {
	pub fn get_peer(&self, key: &str) -> Option<&Peer> {
		self.status.as_ref()?.peers.iter().find(|x| x.key == key)
	}
	pub fn remove_peer(&mut self, key: &str) {
		if let Some(status) = self.status.as_mut() {
			status.peers.retain(|x| x.key != key);
		}
	}
	pub fn replace_peer(&mut self, peer: Peer) {
		if let Some(status) = self.status.as_mut() {
			status.peers.retain(|x| x.key != peer.key);
			status.peers.push(peer);
		}
	}
	pub fn add_peer(&mut self, peer: Peer) {
		if let Some(status) = self.status.as_mut() {
			status.peers.push(peer);
		}
	}
	pub fn copy(&self) -> Self {
		self.clone()
	}
}

impl Default for Discovery {
	fn default() -> Self {
		Self {
			port: DEFAULT_WG_PORT,
			interval: None,
			stuns: DEFAULT_PUB_STUN_SERVERS.iter().map(|x| x.to_string()).collect(),
			pubip: DEFAULT_PUBIP_DISCOVERY
				.iter()
				.map(|x| Pubip {
					url: x.to_string(),
					regex: None,
				})
				.collect(),
			passive: None,
		}
	}
}

impl Wg {
	pub fn random_new() -> Self {
		let hn = hostname::get().map_or_else(|_| None, |x| Some(x.to_string_lossy().to_string()));
		let (pubkey, prikey) = util::new_key_pair();
		Self {
			name: hn,
			public: pubkey,
			private: Some(prikey),
			port: DEFAULT_WG_PORT,
			ip: vec![],
		}
	}
	pub fn clone_to_share(&self) -> Wg {
		Self {
			name: self.name.clone(),
			public: self.public.clone(),
			private: None,
			port: self.port,
			ip: self.ip.clone(),
		}
	}
}

pub fn read_config_file(p: impl AsRef<Path>) -> Result<WgConfig, Box<dyn error::Error>> {
	let file = fs::File::open(&p)?;
	let buf_reader = io::BufReader::new(file);
	let config = serde_yaml::from_reader(buf_reader)?;
	Ok(config)
}

pub fn load_all_net(config_dir: impl AsRef<Path>) -> Vec<WgConfig> {
	let mut nets = Vec::new();
	if !config_dir.as_ref().is_dir() {
		return nets;
	}
	for entry in fs::read_dir(config_dir).unwrap() {
		let path = entry.unwrap().path();
		if !path.is_file() || path.extension() != Some("yaml".as_ref()) {
			continue;
		}
		match read_config_file(&path) {
			Ok(conf) => {
				nets.push(conf);
			}
			Err(e) => {
				error!("cannot load config from {}: {}, skiping", path.display(), e);
			}
		}
	}
	nets
}
pub fn load_all_net_map(config_dir: impl AsRef<Path>) -> HashMap<PathBuf, WgConfig> {
	let mut nets = HashMap::new();
	for entry in fs::read_dir(config_dir).unwrap() {
		let path = entry.unwrap().path();
		if !path.is_file() || path.extension() != Some("yaml".as_ref()) {
			continue;
		}
		match read_config_file(&path) {
			Ok(conf) => {
				nets.insert(path.clone(), conf);
			}
			Err(e) => {
				error!("cannot load config from {}: {}, skiping", path.display(), e);
			}
		}
	}
	nets
}
impl Display for AllowPolicy {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			AllowPolicy::Public => f.write_str("public"),
			AllowPolicy::Private => f.write_str("private"),
		}
	}
}
impl InterfacePolicy {
	pub fn use_def_route(self: &Self) -> bool {
		self.interface.is_none() && self.block_interface_regex.is_none() && self.allow_interface_regex.is_none()
	}
}

pub fn key_pair_is_valid(pubkey: &str, prikey: &str) -> bool {
	let pri_key = base64::prelude::BASE64_STANDARD.decode(prikey);
	let pri_key = match pri_key {
		Ok(p) => {
			if p.len() != 32 {
				return false;
			}
			let mut pp: [u8; 32] = [0; 32];
			pp.copy_from_slice(&p);
			pp
		}
		Err(_) => return false,
	};

	let pri_key = StaticSecret::from(pri_key);

	let pub_key = base64::prelude::BASE64_STANDARD.encode(PublicKey::from(&pri_key));
	if pub_key != pubkey {
		return false;
	}
	true
}

pub fn verify_net_config(conf: &WgConfig) -> bool {
	// verify wg
	{
		if conf.wg.port == 0 {
			return false;
		}

		if !key_pair_is_valid(&conf.wg.public, &conf.wg.private.as_ref().unwrap()) {
			return false;
		}
	}

	true
}
