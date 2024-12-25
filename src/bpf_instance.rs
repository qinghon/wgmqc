use crate::*;
use anyhow::Result;
#[cfg(not(target_os = "linux"))]
use io;
use log::{debug, error};
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
pub(crate) struct UpdateIntfs {
	pub(crate) netid: [u8; 32],
	pub(crate) ip: Option<Vec<IpAddr>>,

	pub(crate) intfs: Option<Vec<u32>>,
	pub(crate) portmaps: Option<Vec<(u16, u16)>>,
	pub(crate) portmaps_out: Option<Vec<(u16, u16)>>,
}
impl UpdateIntfs {
	fn is_empty(&self) -> bool {
		self.ip.is_none() && self.intfs.is_none() && self.portmaps.is_none() && self.portmaps_out.is_none()
	}
}

#[cfg(not(target_os = "linux"))]
pub async fn bpf_event_loop() -> Result<()> {
	Err(io::Error::new(
		io::ErrorKind::Unsupported,
		"oh no! why ebpf not support for no-linux platform!",
	))
}

#[cfg(target_os = "linux")]
pub async fn bpf_event_loop(
	main_cancel: CancellationToken,
	mut event_rx: tokio::sync::mpsc::Receiver<UpdateIntfs>,
	ok_event: tokio::sync::oneshot::Sender<bool>,
) -> Result<()> {
	let open_object = Box::new(MaybeUninit::uninit());

	let mut instence = skel::Instance::new(Box::leak(open_object))?;

	let mut prev_allow_ips = HashSet::new();
	let mut prev_portmaps = HashSet::new();
	let mut prev_portmaps_out = HashSet::new();
	let mut prev_hook_intfs = HashSet::new();

	let _ = ok_event.send(true);

	let mut net_state = HashMap::new();

	loop {
		tokio::select! {
			_ = main_cancel.cancelled() => break,
			event_ = event_rx.recv() => {
				if event_.is_none() {
					break;
				}
				let event = event_.unwrap();
				let netvalue = net_state.get(&event.netid);

				match (netvalue, event.is_empty()) {
					(None, true) => continue,
					(None, false) => {
						net_state.insert(event.netid, (event.ip, event.intfs, event.portmaps, event.portmaps_out));
					},
					(Some(_), true) => {
						net_state.remove(&event.netid);
					},
					(Some(_), false) => {
						net_state.insert(event.netid, (event.ip, event.intfs, event.portmaps, event.portmaps_out));
					}
				}
				
				let mut allow_ips = HashSet::new();
				let mut portmaps = HashSet::new();
				let mut hook_intfs = HashSet::new();
				let mut portmaps_out = HashSet::new();
				for (_,v) in net_state.iter() {
					if let Some(ips) = &v.0 {
						for ip in ips {
							allow_ips.insert(ip.clone());
						}
					}
					if let Some(intfs) = &v.1 {
						for intf in intfs {
							hook_intfs.insert(*intf);
						}
					}
					if let Some(portmap_list) = &v.2 {
						for port in portmap_list {
							portmaps.insert(port.clone());
						}
					}
					if let Some(portmap_list) = &v.3 {
						for port in portmap_list {
							portmaps_out.insert(port.clone());
						}
					}
				}

				if allow_ips!= prev_allow_ips {
					let remove = prev_allow_ips.difference(&allow_ips);
					let add = allow_ips.difference(&prev_allow_ips);
					for rem in remove {
						let res = instence.del_localip(*rem);
						if res.is_err() {
							error!("cannot remove ip: {} from allow_ips map: {}", rem, res.err().unwrap());
						}
					}
					for ad in add {
						let res = instence.add_localip(*ad);
						if res.is_err() {
							error!("cannot add ip: {} from allow_ips map: {}", ad, res.err().unwrap());
						}
					}
				}
				if portmaps != prev_portmaps {
					let remove = prev_portmaps.difference(&portmaps);
					let add = portmaps.difference(&prev_portmaps);
					for rem in remove {
						let res = instence.del_port_pair(rem.0);
						if res.is_err() {
							error!("cannot remove portmap: {:?} from sock_in_map: {}", rem, res.err().unwrap());
						}
					}
					for ad in add {
						let res = instence.add_port_pair(ad.0, ad.1);
						if res.is_err() {
							error!("cannot add portmap: {:?} from allow_ips map: {}", ad, res.err().unwrap());
						}
						debug!("add ingress port map {}=>{}", ad.0, ad.1);
					}
				}
				if portmaps_out != prev_portmaps_out {
					let remove = prev_portmaps_out.difference(&portmaps_out);
					let add = portmaps_out.difference(&prev_portmaps_out);
					for rem in remove {
						let res = instence.del_out_port_pair(rem.0);
						if res.is_err() {
							error!("cannot remove portmap: {:?} from sock_in_map: {}", rem, res.err().unwrap());
						}
					}
					for ad in add {
						let res = instence.add_out_port_pair(ad.0, ad.1);
						if res.is_err() {
							error!("cannot add portmap: {:?} from allow_ips map: {}", ad, res.err().unwrap());
						}
						debug!("add egress port map {}=>{}", ad.0, ad.1);
					}
				}
				if hook_intfs != prev_hook_intfs {
					let remove = prev_hook_intfs.difference(&hook_intfs);
					let add = hook_intfs.difference(&prev_hook_intfs);
					for rem in remove {
						let res = instence.detach(*rem);
						if res.is_err() {
							error!("cannot unhook intf: {} from sock_in_map: {}", rem, res.err().unwrap());
						}
					}
					for ad in add {
						let res = instence.attach(*ad);
						if res.is_err() {
							error!("cannot hook: {} from allow_ips map: {}", ad, res.err().unwrap());
						}
						debug!("add attach bpf tc to ifindex: {}", *ad);
					}
				}
				prev_allow_ips = allow_ips;
				prev_portmaps = portmaps;
				prev_portmaps_out = portmaps_out;
				prev_hook_intfs = hook_intfs;
			}

		}
	}

	instence.detach_all()?;
	drop(instence);

	Ok(())
}
