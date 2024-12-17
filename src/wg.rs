use crate::config;
use crate::config::Peer;
use base64::Engine;
use defguard_wireguard_rs::error::WireguardInterfaceError;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::{InterfaceConfiguration, WGApi, WireguardInterfaceApi};
use log::{debug, info};
use std::net::SocketAddr;
use std::time::SystemTime;

pub(crate) fn keystr_to_key(s: &str) -> Option<defguard_wireguard_rs::key::Key> {
	let pri_key = base64::prelude::BASE64_STANDARD.decode(s);
	match pri_key {
		Ok(p) => {
			if p.len() != 32 {
				return None;
			}
			match defguard_wireguard_rs::key::Key::try_from(p.as_slice()) {
				Ok(k) => Some(k),
				Err(_) => None,
			}
		}
		Err(_) => None,
	}
}

pub(crate) struct WgIntf {
	wgapi: WGApi,
	cur_conf: InterfaceConfiguration,
	ifname: String,
}
impl WgIntf {
	pub fn new(ifname: &str, wg: &config::Wg, peers: Option<Vec<Peer>>) -> Result<Self, WireguardInterfaceError> {
		let wgapi = WGApi::new(ifname.to_string(), false)?;
		// Create host interfaces
		wgapi.create_interface()?;

		let def_peers = if let Some(peers) = peers {
			peers
				.iter()
				.map(|x| defguard_wireguard_rs::host::Peer {
					public_key: keystr_to_key(&x.key).unwrap(),
					endpoint: x.endpoint,
					persistent_keepalive_interval: Some(20),
					allowed_ips: x.allow_ips.iter().map(|x| IpAddrMask::new(x.addr(), x.max_prefix_len())).collect(),
					..Default::default()
				})
				.collect()
		} else {
			vec![]
		};

		// Configure host interface
		let interface_config = InterfaceConfiguration {
			name: ifname.to_string(),
			prvkey: wg.private.clone().unwrap(),
			address: wg.ip[0].to_string(),
			port: wg.port as _,
			peers: def_peers,
		};

		wgapi.configure_interface(&interface_config)?;
		Ok(Self {
			wgapi,
			ifname: ifname.to_string(),
			cur_conf: interface_config,
		})
	}
	pub fn sync_config(&mut self, wg: &config::Wg, peers: &Vec<Peer>) -> Result<(), WireguardInterfaceError> {
		debug!("start sync wg interface: {}", self.ifname);
		let host = self.wgapi.read_interface_data()?;
		// debug!("get host prvkey:{:?} status: {:?}", host.private_key, host);
		let mut cur_conf = self.cur_conf.clone();

		let mut config_changed = false;
		{
			let private_key = keystr_to_key(wg.private.as_ref().unwrap()).unwrap();
			let mut array = private_key.as_array();
			array[0] &= 0xf8;
			array[31] &= 0xef;
			let private_key = defguard_wireguard_rs::key::Key::try_from(array.as_slice()).unwrap();

			if host.listen_port != wg.port {
				debug!(
					"{} need update config: prv={:?} port={}",
					self.ifname, private_key, wg.port
				);
				cur_conf.port = wg.port as u32;
				cur_conf.prvkey = wg.private.as_ref().unwrap().clone();
				config_changed = true;
			}
			if config_changed {
				self.wgapi.configure_interface(&cur_conf)?;
				self.cur_conf = cur_conf.clone();
				info!("{} update config", self.ifname);
			}
		}
		// peer 更新与添加
		config_changed = false;
		{
			for peer in peers {
				let update_k = keystr_to_key(&peer.key).unwrap();
				let host_peer_exist = host.peers.contains_key(&update_k);
				let self_peer_exist = self.cur_conf.peers.iter().any(|x| x.public_key == update_k);
				let update_peer_allow_ips =
					peer.allow_ips.iter().map(|x| IpAddrMask::new(x.addr(), x.max_prefix_len())).collect();
				match (host_peer_exist, self_peer_exist) {
					(true, true) => {
						let host_peer = host.peers.get(&update_k).unwrap();
						let self_peer = self.cur_conf.peers.iter_mut().find(|x| x.public_key == update_k).unwrap();
						self_peer.endpoint = peer.endpoint;
						self_peer.allowed_ips = update_peer_allow_ips;
						self_peer.persistent_keepalive_interval = Some(20);

						if self_peer.allowed_ips != host_peer.allowed_ips
							|| self_peer.endpoint != host_peer.endpoint
							|| self_peer.persistent_keepalive_interval != host_peer.persistent_keepalive_interval
						{
							config_changed = true;
						}
						if config_changed {
							info!(
								"{} update peer \"{}\" endpint={:?} allow_ip={:?}",
								self.ifname,
								peer.name.as_ref().unwrap_or(&peer.key),
								peer.endpoint,
								peer.allow_ips
							);
							self.wgapi.configure_peer(
								self.cur_conf.peers.iter().find(|x| x.public_key == update_k).unwrap(),
							)?;
						}
					}
					(true, false) => {
						let host_peer = host.peers.get(&update_k).unwrap();
						self.cur_conf.peers.push(host_peer.clone());
					}
					(false, true) => {
						let self_peer = self.cur_conf.peers.iter_mut().find(|x| x.public_key == update_k).unwrap();
						self_peer.endpoint = peer.endpoint;
						self_peer.allowed_ips = update_peer_allow_ips;
						self_peer.persistent_keepalive_interval = Some(20);
						info!(
							"{} add peer \"{}\" endpoint={:?} allow_ip={:?}",
							self.ifname,
							peer.name.as_ref().unwrap_or(&peer.key),
							peer.endpoint,
							peer.allow_ips
						);
						self.wgapi
							.configure_peer(self.cur_conf.peers.iter().find(|x| x.public_key == update_k).unwrap())?;
					}
					(false, false) => {
						let self_peer = defguard_wireguard_rs::host::Peer {
							public_key: update_k,
							endpoint: peer.endpoint,
							persistent_keepalive_interval: Some(20),
							allowed_ips: update_peer_allow_ips,
							..Default::default()
						};
						info!(
							"{} add peer \"{}\" endpoint={:?} allow_ip={:?}",
							self.ifname,
							peer.name.as_ref().unwrap_or(&peer.key),
							peer.endpoint,
							peer.allow_ips
						);
						self.wgapi.configure_peer(&self_peer)?;
						self.cur_conf.peers.push(self_peer);
					}
				}
			}
		}
		// peer 删除
		{
			for (key, _) in host.peers {
				let update_peer_exist = peers.iter().position(|x| keystr_to_key(x.key.as_str()).unwrap() == key);
				let self_peer_exist = self.cur_conf.peers.iter().position(|x| x.public_key == key);
				match (update_peer_exist, self_peer_exist) {
					(None, Some(pos)) => {
						info!("{} remove peer {}", self.ifname, key);
						self.wgapi.remove_peer(&key)?;
						self.cur_conf.peers.swap_remove(pos);
					}
					(None, None) => {
						info!("{} remove peer {}", self.ifname, key);
						self.wgapi.remove_peer(&key)?;
					}
					(Some(_), _) => {}
				}
			}
		}

		Ok(())
	}

	pub fn get_peer_last_handshake(&self, pubkey: &str) -> Option<SystemTime> {
		let host = match self.wgapi.read_interface_data() {
			Ok(x) => x,
			Err(_) => return None,
		};
		let k = keystr_to_key(pubkey).unwrap();

		if let Some(peer) = host.peers.get(&k) {
			peer.last_handshake
		} else {
			None
		}
	}
	pub fn get_peer_endpoint(&self, pubkey: &str) -> Option<SocketAddr> {
		let host = match self.wgapi.read_interface_data() {
			Ok(x) => x,
			Err(_) => return None,
		};
		let k = keystr_to_key(pubkey).unwrap();

		if let Some(peer) = host.peers.get(&k) {
			peer.endpoint
		} else {
			None
		}
	}

	pub fn remove(&self) -> Result<(), WireguardInterfaceError> {
		self.wgapi.remove_interface()
	}
}
