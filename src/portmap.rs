use crate::util;
use crate::util::Key;
use anyhow::Error;
use igd_next::Gateway;
use log::{debug, error, info, warn};
pub(crate) use natpmp_ng::Protocol;
use natpmp_ng::Response;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time;
use std::time::Duration;
use tokio::io;
use tokio_util::sync::CancellationToken;

const DEF_LEASE_DURATION: u32 = 7200u32;

pub(crate) enum MapAction {
	AddMaps {
		key: util::Key,
		ports: Vec<(u16, Protocol)>,
		intfs: Vec<netdev::Interface>,
		chan: tokio::sync::mpsc::Sender<MapUpdate>,
	},
}

#[derive(Debug)]
pub(crate) enum MapUpdate {
	Pubip(Vec<IpAddr>),
	// pub-port, pri-port
	Port(Vec<(u16, u16, Protocol)>),
}

pub(crate) struct NetEntry {
	pub ports: Vec<(u16, Protocol)>,
	pub intfs: Vec<netdev::Interface>,
	pub last_update: time::SystemTime,
	pub private_ip: Option<IpAddr>,
	pub mapped_port: Vec<(u16, u16, Protocol)>,
	pub chan: tokio::sync::mpsc::Sender<MapUpdate>,
}
impl NetEntry {
	fn update_private_ip(&mut self, def_gw: Option<IpAddr>) {
		if def_gw.is_none() {
			return;
		}
		let gw_ip = def_gw.unwrap();
		for intf in &self.intfs {
			match &gw_ip {
				IpAddr::V4(ip4) => {
					for ip in intf.ipv4.iter() {
						if ip.contains(ip4) {
							self.private_ip = Some(ip.addr().into());
						}
					}
				}
				IpAddr::V6(ip6) => {
					for ip in intf.ipv6.iter() {
						if ip.contains(ip6) {
							self.private_ip = Some(ip.addr().into());
						}
					}
				}
			}
		}
	}
	async fn try_to_map_port(&mut self, def_gw: &Option<IpAddr>, upnp_gw: &Option<Gateway>, pubip: &IpAddr) {
		if self.private_ip.is_none() {
			self.update_private_ip(def_gw.clone());
			if self.private_ip.is_none() {
				return;
			}
		}
		match self.last_update.elapsed() {
			Ok(d) => {
				if d < Duration::from_secs(DEF_LEASE_DURATION as u64) {
					return;
				}
			}
			Err(_) => return,
		}
		self.mapped_port.clear();
		for (port, proto) in self.ports.iter() {
			let try_pub_port = port.clone();
			for off in 0..65535 {
				if try_pub_port + off == 0 {
					continue;
				}
				match tokio::time::timeout(
					Duration::from_secs(3),
					start_action_map(
						def_gw.clone(),
						upnp_gw.clone(),
						*proto,
						SocketAddr::new(self.private_ip.unwrap(), *port),
						try_pub_port + off,
					),
				)
				.await
				{
					Ok(Ok(p)) => {
						info!("mapped {}:{} => {}:{}", pubip, p, self.private_ip.unwrap(), *port);
						self.mapped_port.push((p, *port, *proto));
						break;
					}
					Ok(Err(e)) => {
						error!("cannot get map port {}: {}", try_pub_port + off, e);
					}
					Err(_) => {
						break;
					}
				}
			}
		}
		self.last_update = time::SystemTime::now();
		let _ = self.chan.send(MapUpdate::Port(self.mapped_port.clone())).await;
	}
}

async fn start_action_map_upnp(
	upnp_gw: Option<Gateway>,
	protocol: Protocol,
	private_addr: SocketAddr,
	public_port: u16,
) -> Result<u16, Error> {
	match upnp_gw.unwrap().add_port(
		if protocol == Protocol::TCP {
			igd_next::PortMappingProtocol::TCP
		} else {
			igd_next::PortMappingProtocol::UDP
		},
		public_port,
		private_addr,
		7200,
		"wgmqc",
	) {
		Ok(_) => Ok(public_port),
		Err(e) => Err(e.into()),
	}
}
async fn start_action_map_pmp(
	def_gw: IpAddr,
	protocol: Protocol,
	private_addr: SocketAddr,
	public_port: u16,
) -> Result<u16, Error> {
	let IpAddr::V4(ip4) = def_gw else {
		return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid IP address").into());
	};

	let n = natpmp_ng::new_tokio_natpmp_with(ip4).await?;

	let err = n.send_port_mapping_request(protocol, private_addr.port(), public_port, 7200).await;
	if err.is_err() {
		error!("cannot sendmap port for nap-pmp: {}", err.err().unwrap());
		return Err(err.err().unwrap().into());
	}
	match n.read_response_or_retry().await? {
		Response::Gateway(p) => {
			error!("read unexpected gateway response from nap-pmp: {:?}", p);
			Err(io::Error::new(io::ErrorKind::Other, "read unexpected gateway response from nap-pmp").into())
		}
		Response::UDP(o) => Ok(o.public_port()),
		Response::TCP(o) => Ok(o.public_port()),
	}
}

async fn start_action_map(
	def_gw: Option<IpAddr>,
	upnp_gw: Option<Gateway>,
	protocol: Protocol,
	private_addr: SocketAddr,
	public_port: u16,
) -> Result<u16, Error> {
	
	if let Some(gw) = def_gw {
		if let Ok(Ok(p)) = tokio::time::timeout(Duration::from_secs(2), start_action_map_pmp(
			gw,
			protocol,
			private_addr,
			public_port,
		)).await {
  				return Ok(p);
		}
	}
	if upnp_gw.is_some() {
		return start_action_map_upnp(upnp_gw, protocol, private_addr, public_port).await;
	}
	Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "cannot map port for any backend").into())
}

async fn start_get_pubip_pmp(def_gw: IpAddr) -> Result<IpAddr, Error> {
	let IpAddr::V4(ip4) = def_gw else {
		return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid IP address").into());
	};
	let mut n = natpmp_ng::new_tokio_natpmp_with(ip4).await?;
	let _ = n.send_public_address_request().await?;

	debug!("waiting nat-pmp response");
	let p = n.read_response_or_retry().await?;
	match p {
		Response::Gateway(p) => Ok(IpAddr::from(p.public_address().clone())),

		_ => Err(Error::from(io::Error::new(
			io::ErrorKind::AddrNotAvailable,
			"cannot get public address response",
		))),
	}
}
async fn start_get_pubip_upnp(upnp_gw: Option<Gateway>) -> Result<IpAddr, Error> {
	let ipaddr = upnp_gw.clone().unwrap().get_external_ip()?;
	Ok(IpAddr::from(ipaddr))
}

async fn start_get_external_ip(def_gw: Option<IpAddr>, upnp_gw: Option<Gateway>) -> Result<IpAddr, Error> {
	let mut set = tokio::task::JoinSet::new();
	if def_gw.is_some() {
		set.spawn(start_get_pubip_pmp(def_gw.unwrap()));
	}

	if upnp_gw.is_some() {
		set.spawn(start_get_pubip_upnp(upnp_gw));
	}
	while let Some(res) = set.join_next().await {
		match res {
			Ok(Ok(p)) => {
				return Ok(IpAddr::from(p));
			}
			Err(e) => {
				error!("cannot get external ip: {}", e);
			}
			_ => {}
		}
	}
	Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "cannot get pubip for any backend").into())
}

pub(crate) async fn portmap_loop(mut chan: tokio::sync::mpsc::Receiver<MapAction>, main_cancel: CancellationToken) {
	let upnp_gw_fn = || igd_next::search_gateway(Default::default()).map_or_else(|_| None, |x| Some(x));
	let def_gw_fn = || {
		netdev::get_default_gateway().map_or_else(
			|_| None,
			|x| {
				if !x.ipv4.is_empty() {
					Some(x.ipv4[0].into())
				} else if !x.ipv6.is_empty() {
					Some(x.ipv6[0].into())
				} else {
					None
				}
			},
		)
	};
	let set_def_gw_from_upnp = |upnp_gw: &Option<Gateway>, def_gw: &Option<_>| match (upnp_gw, def_gw) {
		(None, None) => None,
		(Some(gw), _) => {
			warn!("upnp igd available as {}, ignor local-route gateway", gw.addr.ip());
			Some(gw.addr.ip())
		}
		(_, p @ Some(_)) => *p,
	};

	let mut upnp_gw = upnp_gw_fn();
	let mut def_gw: Option<IpAddr> = def_gw_fn();

	if upnp_gw.is_none() && def_gw.is_none() {
		error!("cannot get default gateway from upnp or local-route");
	}
	def_gw = set_def_gw_from_upnp(&upnp_gw, &def_gw);
	let mut interval = tokio::time::interval(time::Duration::from_secs(120));
	let mut pubip = util::IPADDRV4_UNSPECIFIED;

	match tokio::time::timeout(Duration::from_secs(3), start_get_external_ip(def_gw, upnp_gw.clone())).await {
		Ok(Ok(ip)) => pubip = ip,
		Err(_) => {}
		_ => {}
	}

	let mut port_maps: HashMap<Key, NetEntry> = HashMap::new();

	let _get_min_sleep_time = |maps: &HashMap<Key, NetEntry>| {
		if let Some((_, entry)) = maps.iter().min_by_key(|(_, entry)| entry.last_update) {
			if let Ok(d) = entry.last_update.elapsed() {
				min(
					max(
						Duration::from_secs(DEF_LEASE_DURATION as u64).saturating_sub(d),
						Duration::from_secs(1),
					),
					Duration::from_secs(DEF_LEASE_DURATION as u64),
				)
			} else {
				Duration::from_secs(DEF_LEASE_DURATION as u64)
			}
		} else {
			Duration::from_secs(24 * 60 * 60)
		}
	};
	let mut sleep_event;
	loop {
		sleep_event = tokio::time::sleep(_get_min_sleep_time(&port_maps));
		tokio::select! {
			_ = sleep_event => {

				port_maps.retain(|_,entry| !entry.chan.is_closed());
				if def_gw.is_none() && def_gw_fn().is_none() {
					continue;
				}
				for entry in port_maps.values_mut() {
					entry.try_to_map_port(&def_gw, &upnp_gw, &pubip).await;
				}

			},
			_ = interval.tick() => {
				if upnp_gw.is_none() {
					upnp_gw = upnp_gw_fn();
				}
				if def_gw.is_none() {
					def_gw = def_gw_fn();
				}
				if def_gw.is_none() {
					def_gw = set_def_gw_from_upnp(&upnp_gw, &def_gw);
				}
				let old_pubip = pubip;
				match tokio::time::timeout(Duration::from_secs(3),
						start_get_external_ip(def_gw, upnp_gw.clone())
					).await {
					Ok(Ok(ip)) => pubip = ip,
					Err(_) => {}
					_ => {}
				}
				if pubip != old_pubip {
					for (_, entry) in port_maps.iter_mut() {
						if entry.chan.is_closed() {
							continue;
						}
						let _ = entry.chan.send(MapUpdate::Pubip(vec![pubip.clone()])).await;
					}
				}
			},
			_ = main_cancel.cancelled() => {
				break;
			}
			msg = chan.recv() => {
				if msg.is_none() {
					return;
				}
				let _msg = msg.unwrap();

				if upnp_gw.is_none() && def_gw.is_none() {
					upnp_gw = upnp_gw_fn();
					def_gw = def_gw_fn();

				}

				def_gw = set_def_gw_from_upnp(&upnp_gw, &def_gw);

				match _msg {
					MapAction::AddMaps {key,ports,intfs,chan} => {
						if ports.is_empty() && port_maps.contains_key(&key) {
							port_maps.remove(&key);
							continue;
						}
						let mut entry = NetEntry {
							mapped_port: Vec::with_capacity(ports.len()),
							ports,
							intfs,
							last_update: time::UNIX_EPOCH,
							private_ip: None,
							chan
						};
						entry.update_private_ip(def_gw.clone());
						if pubip != util::IPADDRV4_UNSPECIFIED {
							let _ = entry.chan.send(MapUpdate::Pubip(vec![pubip.clone()])).await;
						}
						port_maps.insert(key, entry);
					}
				}
			}
		}
	}
}
