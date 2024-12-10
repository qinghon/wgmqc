use igd_next;
use igd_next::Gateway;
use log::{error, warn};
use natpmp_ng;
use natpmp_ng::{Protocol, Response};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time;
use tokio::io;
use tokio_util::sync::CancellationToken;

pub(crate) enum MapAction {
	// map port to public
	Map {
		protocol: Protocol,
		private_addr: SocketAddr,
		public_port: u16,
		chan: tokio::sync::oneshot::Sender<Result<(), io::Error>>,
	},
	// get public ip
	GetPub {
		chan: tokio::sync::oneshot::Sender<Result<IpAddr, io::Error>>,
	},
}

async fn start_action_map(
	def_gw: &Option<Ipv4Addr>,
	upnp_gw: &Option<Gateway>,
	protocol: Protocol,
	private_addr: SocketAddr,
	public_port: u16,
	chan: tokio::sync::oneshot::Sender<Result<(), io::Error>>,
) {
	if def_gw.is_some() {
		match natpmp_ng::new_tokio_natpmp_with(def_gw.clone().unwrap()).await {
			Ok(n) => '_inner: {
				let err = n
					.send_port_mapping_request(protocol, private_addr.port(), public_port, 7200)
					.await;
				if err.is_err() {
					error!("cannot sendmap port for nap-pmp: {}", err.err().unwrap());
					break '_inner;
				}
				let res = n.read_response_or_retry().await;
				if res.is_err() {
					error!("cannot map port for nap-pmp: {}", res.err().unwrap());
					break '_inner;
				}

				let _ = chan.send(Ok(()));
				return;
			}
			Err(_) => {}
		}
	}
	if upnp_gw.is_some() {
		let res = upnp_gw.clone().unwrap().add_port(
			if protocol == Protocol::TCP {
				igd_next::PortMappingProtocol::TCP
			} else {
				igd_next::PortMappingProtocol::UDP
			},
			public_port,
			private_addr,
			7200,
			"wgmqc",
		);
		if res.is_ok() {
			let _ = chan.send(Ok(()));
			return;
		}
		error!("cannot map port for upnp: {}", res.err().unwrap());
	}
	let _ = chan.send(Err(io::Error::new(
		io::ErrorKind::Other,
		"cannot send portmaping from natpmp or upnp:".to_string(),
	)));
}

async fn start_get_external_ip(
	def_gw: &Option<Ipv4Addr>,
	upnp_gw: &Option<Gateway>,
	chan: tokio::sync::oneshot::Sender<Result<IpAddr, io::Error>>,
) {
	if def_gw.is_some() {
		match natpmp_ng::new_tokio_natpmp_with(def_gw.clone().unwrap()).await {
			Ok(mut n) => '_inner: {
				let err = n.send_public_address_request().await;
				if err.is_err() {
					error!("cannot sendmap port for nap-pmp: {}", err.err().unwrap());
					break '_inner;
				}
				let res = n.read_response_or_retry().await;
				if res.is_err() {
					error!("cannot map port for nap-pmp: {}", res.err().unwrap());
					break '_inner;
				}
				match res.unwrap() {
					Response::Gateway(p) => {
						let _ = chan.send(Ok(IpAddr::from(p.public_address().clone())));
					}
					_ => {}
				}
				return;
			}
			Err(_) => {}
		}
	}
	if upnp_gw.is_some() {
		let res = upnp_gw.clone().unwrap().get_external_ip();
		if res.is_ok() {
			let _ = chan.send(Ok(res.unwrap()));
			return;
		}
		error!("cannot map port for upnp: {}", res.err().unwrap());
	}
	let _ = chan.send(Err(io::Error::new(
		io::ErrorKind::Other,
		"cannot get public ip from natpmp or upnp:".to_string(),
	)));
}

pub(crate) async fn portmap_loop(mut chan: tokio::sync::mpsc::Receiver<MapAction>, main_cancel: CancellationToken) {
	let upnp_gw_fn = || igd_next::search_gateway(Default::default()).map_or_else(|_| None, |x| Some(x));
	let def_gw_fn = || {
		netdev::get_default_gateway().map_or_else(
			|_| None,
			|x| {
				if x.ipv4.is_empty() { None } else { Some(x.ipv4[0]) }
			},
		)
	};
	let set_def_gw_from_upnp = |upnp_gw: &Option<Gateway>, def_gw: &Option<Ipv4Addr>| match (upnp_gw, def_gw) {
		(None, None) => None,
		(Some(_), None) => {
			warn!("get gateway fail from local-route, but upnp available, using!");
			match upnp_gw.clone().unwrap().addr.ip() {
				IpAddr::V4(ip) => Some(ip),
				IpAddr::V6(_) => None,
			}
		}
		(_, p @ Some(_)) => p.clone(),
	};

	let mut upnp_gw = upnp_gw_fn();
	let mut def_gw = def_gw_fn();

	if upnp_gw.is_none() && def_gw.is_none() {
		error!("cannot get default gateway from upnp or local-route");
	}
	def_gw = set_def_gw_from_upnp(&upnp_gw, &def_gw);
	let mut interval = tokio::time::interval(time::Duration::from_secs(120));

	loop {
		tokio::select! {
			_ = interval.tick() => {
				upnp_gw = upnp_gw_fn();
				def_gw = def_gw_fn();
				if def_gw.is_none(){
					def_gw = set_def_gw_from_upnp(&upnp_gw, &def_gw);
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
					MapAction::Map{ protocol,private_addr,public_port,chan } => {
						if upnp_gw.is_none() && def_gw.is_none() {
							error!("cannot get default gateway from upnp or local-route, cannot add port-map");
							let _ = chan.send(Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "cannot get gateway")));
							continue;
						}
						start_action_map(&def_gw, &upnp_gw, protocol, private_addr, public_port, chan).await;
					},
					MapAction::GetPub {chan } => {
						if upnp_gw.is_none() && def_gw.is_none() {
							error!("cannot get default gateway from upnp or local-route, cannot add port-map");
							let _ = chan.send(Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "cannot get gateway")));
							continue;
						}
						start_get_external_ip(&def_gw, &upnp_gw, chan).await;
					}
				}
			}
		}
	}
}
