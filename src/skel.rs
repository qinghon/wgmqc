use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, OpenObject, TC_EGRESS, TC_INGRESS, TcHook, TcHookBuilder};
use log::{error, info};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::fd::AsFd;
use std::time::Instant;

include!(concat!(env!("OUT_DIR"), "/wgredir.skel.rs"));

pub(crate) struct Instance<'obj> {
	skel: WgredirSkel<'obj>,

	attached_ingress_hook: HashMap<u32, TcHook>,
	attached_egress_hook: HashMap<u32, TcHook>,
}

fn bump_memlock_rlimit() -> Result<()> {
	let rlimit = libc::rlimit {
		rlim_cur: 128 << 20,
		rlim_max: 128 << 20,
	};

	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
		error!("Failed to increase rlimit");
	}

	Ok(())
}

impl<'obj> Instance<'obj> {
	pub(crate) fn new(open_object: &'obj mut MaybeUninit<OpenObject>) -> Result<Instance<'obj>> {
		bump_memlock_rlimit()?;
		let skel_builder = WgredirSkelBuilder::default();

		// let mut open_object = MaybeUninit::uninit();

		let open_skel = skel_builder.open(open_object)?;
		let start = Instant::now();
		let mut skel = open_skel.load()?;
		info!("eBPF programs loaded in {:?}", start.elapsed());
		skel.attach()?;

		Ok(Self {
			skel,
			attached_egress_hook: HashMap::new(),
			attached_ingress_hook: HashMap::new(),
		})
	}
	pub fn add_port_pair(&mut self, from: u16, to: u16) -> Result<()> {
		let from_slice = u16::to_ne_bytes(from);
		let to_slice = (0..libbpf_rs::num_possible_cpus()?).map(|_| u16::to_ne_bytes(to).to_vec()).collect::<Vec<_>>();
		match self.skel.maps.sock_in_map.lookup_percpu(&from_slice, libbpf_rs::MapFlags::ANY) {
			Ok(_) => {
				self.skel.maps.sock_in_map.update_percpu(&from_slice, &to_slice, libbpf_rs::MapFlags::ANY)?;
			}
			Err(e) => {
				error!("Failed to lookup port: {:?}", e);
			}
		}
		Ok(())
	}
	pub fn del_port_pair(&mut self, from: u16) -> Result<()> {
		let from_slice = u16::to_ne_bytes(from);
		self.skel.maps.sock_in_map.delete(&from_slice)?;
		Ok(())
	}

	pub fn add_out_port_pair(&mut self, from: u16, to: u16) -> Result<()> {
		let from_slice = u16::to_ne_bytes(from);
		let to_slice = (0..libbpf_rs::num_possible_cpus()?).map(|_| u16::to_ne_bytes(to).to_vec()).collect::<Vec<_>>();
		match self.skel.maps.sock_out_map.lookup_percpu(&from_slice, libbpf_rs::MapFlags::ANY) {
			Ok(_) => {
				self.skel.maps.sock_out_map.update_percpu(&from_slice, &to_slice, libbpf_rs::MapFlags::ANY)?;
			}
			Err(e) => {
				error!("Failed to lookup port: {:?}", e);
			}
		}
		Ok(())
	}
	pub fn del_out_port_pair(&mut self, from: u16) -> Result<()> {
		let from_slice = u16::to_ne_bytes(from);
		self.skel.maps.sock_out_map.delete(&from_slice)?;
		Ok(())
	}

	pub fn add_localip(&mut self, ip: IpAddr) -> Result<()> {
		let value = (0..libbpf_rs::num_possible_cpus()?).map(|_| vec![0u8; 1]).collect::<Vec<_>>();
		let mut ip_bytes: [u8; 16] = [0; 16];
		match ip {
			IpAddr::V4(ip4) => {
				ip_bytes[0..4].clone_from_slice(&ip4.octets());
			}
			IpAddr::V6(v) => {
				ip_bytes.copy_from_slice(v.octets().as_ref());
			}
		}
		self.skel.maps.allow_ips.update_percpu(&ip_bytes, &value, libbpf_rs::MapFlags::ANY)?;

		Ok(())
	}
	pub fn del_localip(&mut self, ip: IpAddr) -> Result<()> {
		let mut ip_bytes: [u8; 16] = [0; 16];
		match ip {
			IpAddr::V4(ip4) => {
				ip_bytes[0..4].clone_from_slice(&ip4.octets());
			}
			IpAddr::V6(v) => {
				ip_bytes.copy_from_slice(v.octets().as_ref());
			}
		}
		self.skel.maps.allow_ips.delete(&ip_bytes)?;
		Ok(())
	}

	fn ingress_tc_hook(&self, if_index: u32) -> TcHook {
		// let progs = &self.skel.progs;
		TcHookBuilder::new(self.skel.progs.tc_ingress.as_fd())
			.ifindex(if_index as _)
			.replace(true)
			.handle(1)
			.hook(TC_INGRESS)
	}

	fn egress_tc_hook(&self, if_index: u32) -> TcHook {
		let progs = &self.skel.progs;
		TcHookBuilder::new(progs.tc_egress.as_fd())
			.ifindex(if_index as _)
			.replace(true)
			.handle(1)
			.hook(TC_EGRESS)
	}

	fn attach_if_index(&mut self, if_index: u32) -> Result<()> {
		if !self.attached_egress_hook.contains_key(&if_index) {
			let egress_hook = self.egress_tc_hook(if_index).create()?.attach()?;
			self.attached_egress_hook.insert(if_index, egress_hook);
		}
		if !self.attached_ingress_hook.contains_key(&if_index) {
			let ingress_hook = self.ingress_tc_hook(if_index).create()?.attach()?;
			self.attached_ingress_hook.insert(if_index, ingress_hook);
		}
		Ok(())
	}
	fn detach_if_index(&mut self, if_index: u32) -> Result<()> {
		if let Some(mut hooks) = self.attached_ingress_hook.remove(&if_index) {
			let _ = hooks.detach();
		}
		if let Some(mut hooks) = self.attached_egress_hook.remove(&if_index) {
			let _ = hooks.detach();
		}
		Ok(())
	}

	pub fn attach(&mut self, if_index: u32) -> Result<()> {
		let res = self.attach_if_index(if_index);
		if res.is_err() {
			let _ = self.detach(if_index);
		}
		res
	}
	pub fn detach(&mut self, if_index: u32) -> Result<()> {
		self.detach_if_index(if_index)
	}
	pub fn detach_all(&mut self) -> Result<()> {
		let ifs = self.attached_ingress_hook.keys().map(|k| *k).collect::<Vec<_>>();
		for if_index in ifs.into_iter() {
			self.detach_if_index(if_index)?;
		}
		Ok(())
	}
}
