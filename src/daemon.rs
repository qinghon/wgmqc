use crate::bpf_instance::UpdateIntfs;
use crate::config::{Peer, WgConfig};
use crate::ice::IceAddr;
use crate::mq_msg::{MqMsg, MqMsgType};
use crate::portmap;
use crate::portmap::portmap_loop;
use crate::pubip::get_pubip_list;
use crate::stun::stun_do_trans;
use crate::util::{IPADDRV4_UNSPECIFIED, IPADDRV6_UNSPECIFIED, Ipv6AddrC, SOCKETADDRV4_UNSPECIFIED};
use crate::wg::WgIntf;
use crate::*;
use log::Level::Debug;
use log::{debug, error, info, log_enabled, trace, warn};
use netdev::Interface;
use rumqttc::{ConnectReturnCode, Event, Incoming, MqttOptions, Transport};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

enum NetworkMessage {
	Add((PathBuf, WgConfig)),
	Leave((PathBuf, WgConfig)),
}

#[derive(Debug)]
pub(crate) enum WgCtrlMsg {
	AddPeer {
		wg: config::Wg,
		endpoint: Option<SocketAddr>,
	},
	RemovePeer {
		pubkey: String,
	},
	UpdatePeer {
		wg: config::Wg,
		endpoints: Option<IceAddr>,
		traceroute: Option<Vec<mq_msg::Traceroute>>,
	},
	PubipChanged {
		ips: Vec<IpAddr>,
	},
	Announce {
		wg: config::Wg,
	},
}

pub(crate) type WgConfShare = Arc<arc_swap::ArcSwap<WgConfig>>;

struct MqConnect {
	client: rumqttc::AsyncClient,
	event_loop: rumqttc::EventLoop,
	netname: String,
	prikey: x25519_dalek::StaticSecret,
	admin_prikey: Option<x25519_dalek::StaticSecret>,
	subcribe_path: String,
}

struct EchoServer {
	enable_udp: bool,
	enable_tcp: bool,
	udp_socket: Option<UdpSocket>,
	udp_socket6: Option<UdpSocket>,
	tcp_listener: Option<TcpListener>,
	tcp_listener6: Option<TcpListener>,
}

fn new_ipv6_socket(addr: SocketAddr) -> Result<std::net::UdpSocket, io::Error> {
	let socket = socket2::Socket::new(
		socket2::Domain::IPV6,
		socket2::Type::DGRAM,
		Some(socket2::Protocol::UDP),
	)
	.map_err(|e| io::Error::new(ErrorKind::Other, e))?;

	// socket.set_only_v6(false).map_err(|e|io::Error::new(ErrorKind::Other, e))?;
	socket.set_only_v6(true).unwrap();

	// socket.bind(&addr.into()).map_err(|e|io::Error::new(ErrorKind::AlreadyExists, e))?;
	socket.bind(&addr.into()).unwrap();
	// socket.listen(128).map_err(|e|io::Error::new(ErrorKind::Other, e))?;
	// socket.listen(128).unwrap();

	Ok(socket.into())
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
			_ =cancellation_token.cancelled() => break,
		}
	}
}

impl EchoServer {
	pub(crate) async fn new(udp_port: u16, tcp_port: u16) -> Result<Self, io::Error> {
		let (udp4, udp6) = if udp_port != 0 {
			(
				Some(UdpSocket::bind(SocketAddr::new(IPADDRV4_UNSPECIFIED, udp_port)).await.expect("cannot bind4 udp")),
				Some(UdpSocket::from_std(
					new_ipv6_socket(SocketAddr::new(IPADDRV6_UNSPECIFIED, udp_port)).expect("cannot bind6 udp"),
				)?),
			)
		} else {
			(None, None)
		};
		let (tcp4, tcp6) = if tcp_port != 0 {
			(
				Some(tokio::net::TcpListener::bind(SocketAddr::new(IPADDRV4_UNSPECIFIED, tcp_port)).await?),
				Some(tokio::net::TcpListener::bind(SocketAddr::new(IPADDRV6_UNSPECIFIED, tcp_port)).await?),
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
	pub(crate) fn get_udp_sock(&self) -> &Option<UdpSocket> {
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
		udp4_recv = udp_sock.as_ref().unwrap().recv_from(buf4) => {
			match udp4_recv {
				Err(e) => {
					error!("udp recv error {}", e);
				},
				Ok((p, src)) => {
					trace!("udp recv from {}:{}", p, src);
					if p > 0 {
						let _ = udp_sock.as_ref().unwrap().send_to(&buf4[0..p], src).await;
					}
				}
			}
		},
		udp6_recv = udp_sock6.as_ref().unwrap().recv_from(buf6) => {
			match udp6_recv {
				Err(e) => {
					error!("udp recv error {}", e);
				},
				Ok((p, src)) => {
					trace!("udp recv from {}:{}", p, src);
					if p > 0 {
						let _ = udp_sock.as_ref().unwrap().send_to(&buf6[0..p], src).await;
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

impl MqConnect {
	pub(crate) async fn new(config: WgConfig) -> Result<Self, io::Error> {
		let netname = config.network.name.clone();
		let subcribe_path;
		let prikey;
		let admin_prikey;
		let mqttop;
		{
			let broker = config.network.broker.clone();
			prikey =
				x25519_dalek::StaticSecret::from(util::keystr_to_array(config.wg.private.as_ref().unwrap()).unwrap());
			admin_prikey = if config.network.broker_admin_prikey.is_some() {
				Some(x25519_dalek::StaticSecret::from(
					util::keystr_to_array(config.network.broker_admin_prikey.clone().unwrap().as_str()).unwrap(),
				))
			} else {
				None
			};

			let uri = match url::Url::parse(&broker) {
				Ok(u) => u,
				Err(e) => {
					error!("cannot parse broker url \"{}\": {}", broker, e);
					return Err(Error::new(ErrorKind::InvalidInput, "cannot parse broker url"));
				}
			};
			// 兼容v2的配置23字符
			let mut client_id = String::with_capacity(23);
			client_id.push_str(&config.wg.public[0..16]);
			client_id.push_str(&config.wg.public[37..]);

			// rumqttc url解析有点问题
			let port = uri.port().unwrap_or_else(|| match uri.scheme() {
				"ws" => 80,
				"wss" => 443,
				"tcp" | "mqtt" => 1883,
				"ssl" | "mqtts" => 8883,
				_ => 1883,
			});
			let host = match uri.scheme() {
				"ws" | "wss" => uri.clone().to_string(),
				_ => uri.host().unwrap().to_string(),
			};
			let mut options = MqttOptions::new(client_id, host, port);
			match uri.scheme() {
				"wss" | "ssl" | "mqtts" => {
					// todo: 支持自定义ca证书
					options.set_transport(Transport::wss_with_default_config());
				}
				"ws" => {
					options.set_transport(Transport::Ws);
				}
				_ => {}
			}
			options.set_keep_alive(Duration::from_secs(60));

			if let Some(user) = config.network.mq_user.clone() {
				options.set_credentials(user, config.network.mq_password.as_ref().clone().unwrap());
			}
			subcribe_path = util::base64_to_hex(&config.network.id).unwrap();
			mqttop = options
		};

		let (client, eventloop) = rumqttc::AsyncClient::new(mqttop, 10);
		debug!("mqt sub path: {}", subcribe_path);
		loop {
			match client.subscribe(&subcribe_path, rumqttc::QoS::AtLeastOnce).await {
				Ok(_) => break,
				Err(e) => {
					error!("network {} subscribe err: {}", netname, e);
				}
			}
		}
		Ok(Self {
			client,
			event_loop: eventloop,
			netname,
			prikey,
			admin_prikey,
			subcribe_path,
		})
	}

	pub(crate) fn mq_msg_process(&self, msg: mq_msg::MqMsg) -> Option<WgCtrlMsg> {
		match msg.t {
			MqMsgType::Sign(_) => None,
			MqMsgType::Announce(v) => Some(WgCtrlMsg::Announce { wg: v.wg }),
			MqMsgType::Update(v) => Some(WgCtrlMsg::UpdatePeer {
				wg: v.wg,
				endpoints: Some(v.endpoints),
				traceroute: v.traceroute,
			}),
		}
	}

	pub(crate) async fn recvmsg(&mut self, cancellation_token: &CancellationToken) -> Option<WgCtrlMsg> {
		loop {
			tokio::select! {
				_ = cancellation_token.cancelled() => return None,
				event = self.event_loop.poll() => {
					match event {
						Ok(Event::Incoming(Incoming::ConnAck(ack))) => {
							if ack.code == ConnectReturnCode::Success {
								if let Err(e) = self.client.subscribe(self.subcribe_path.clone(), rumqttc::QoS::AtLeastOnce).await {
									error!("cannot subscribe to {}: {}", self.subcribe_path, e);
								}
							}else {
								warn!("Could not connect to mqtt broker: {:?}", ack.code);
                    			tokio::time::sleep(Duration::from_secs(5)).await;
							}
						},
						Ok(Event::Incoming(Incoming::Publish(msg))) => {
							// debug!("recv other client: {:?}", msg);
							let payload = msg.payload;

							let data:MqMsg = match serde_json::from_slice(&payload) {
								Ok(d) => d,
								Err(e) => {
									debug!("cannot parse payload \"{:?}\": {}", payload, e);
									continue;
								},
							};
								return self.mq_msg_process(data)
						},

						Ok(_) => {
							continue;
						},
						Err(e) => {

								error!("network {} poll err: {}", self.netname, e);
								debug!("mqtt transport: {:?}", self.event_loop.mqtt_options);
								self.event_loop.clean();
								tokio::time::sleep(Duration::from_secs(1)).await;
								continue;
						}
					}
				},
			}
		}
	}
	pub(crate) async fn sendmsg(&mut self, mut msg: mq_msg::MqMsg) -> Result<(), io::Error> {
		if msg.is_admin() {
			if self.admin_prikey.is_some() {
				msg.sign_data(self.admin_prikey.as_ref().unwrap());
			} else {
				error!("network {} no admin key, ignore admin msg send", self.netname);
				debug!("network {} drop send {:?}", self.netname, msg);
			}
		} else {
			msg.sign_data(&self.prikey);
			debug!("network {} send mq msg {:?} ", self.netname, msg)
		}

		let data = match serde_json::to_string(&msg) {
			Ok(d) => d,
			Err(e) => {
				error!("network {} cannot serialize send data {:?}: {}", self.netname, msg, e);
				return Err(io::Error::new(io::ErrorKind::InvalidData, ""));
			}
		};
		let start = Instant::now();
		let ret = self.client.publish(&self.subcribe_path, rumqttc::QoS::AtMostOnce, false, data).await;
		if ret.is_err() {
			if log_enabled!(Debug) {
				debug!(
					"network {} cannot push data {:?}: {}",
					self.netname,
					msg,
					ret.unwrap_err()
				);
			} else {
				error!(
					"network {} cannot push data {:?}: {}",
					self.netname,
					msg.t,
					ret.unwrap_err()
				);
			}
		}
		debug!("network {} send msg time: {:?}", self.netname, start.elapsed());
		Ok(())
	}
}

async fn analyze_tcp_latency(addr: SocketAddr) -> Result<Duration, io::Error> {
	let mut stream = match tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await {
		Ok(s) => s?,
		Err(e) => return Err(Error::from(e)),
	};

	let message = b"ping";
	let start = time::Instant::now(); // 记录发送前的时间
	stream.write_all(message).await?; // 异步发送数据

	// 接收响应
	let mut buffer = [0u8; 1024]; // 接收缓冲区
	let _ = stream.read(&mut buffer).await?;
	let duration = start.elapsed(); // 计算时间差
	Ok(duration)
}

async fn analyze_udp_latency(addr: SocketAddr) -> Result<Duration, io::Error> {
	let udp_sock = tokio::net::UdpSocket::bind(SOCKETADDRV4_UNSPECIFIED).await?;
	udp_sock.connect(addr).await?;

	let message = b"ping";
	let start = time::Instant::now(); // 记录发送前的时间
	udp_sock.send_to(message, addr).await?; // 异步发送数据

	// 接收响应
	let mut buffer = [0u8; 4]; // 接收缓冲区
	let mut interval = tokio::time::interval(time::Duration::from_secs(1));

	tokio::time::timeout(time::Duration::from_secs(3), async {
		loop {
			tokio::select! {
				_ = interval.tick() => {
					udp_sock.send_to(message, addr).await?;
				}
				udp_recv = udp_sock.recv_from(&mut buffer) => {
					let (p, from_addr) = udp_recv?;
					if addr == from_addr && p == message.len() {
						return Ok::<Duration, io::Error>(start.elapsed());
					}
				}
			}
		}
	})
	.await?
}

async fn analyze_addr_latency(addr: SocketAddr, udp: bool) -> Result<Duration, io::Error> {
	if udp {
		analyze_udp_latency(addr).await
	} else {
		analyze_tcp_latency(addr).await
	}
}

async fn analyze_ice_addrs(ice_addr: IceAddr, cancellation_token: CancellationToken) -> Vec<SocketAddr> {
	let mut new_ice_addr: Vec<(SocketAddr, Duration)> = vec![];
	let mut rets = tokio::task::JoinSet::new();
	let udp = ice_addr.support_udp;

	for lan_addr in ice_addr.lan {
		rets.spawn(async move {
			match analyze_addr_latency(lan_addr, udp).await {
				Ok(l) => Ok((lan_addr, l)),
				Err(e) => Err(e),
			}
		});
	}

	for ipv6_addr in ice_addr.ipv6 {
		rets.spawn(async move {
			match analyze_addr_latency(ipv6_addr, udp).await {
				Ok(l) => Ok((ipv6_addr, l)),
				Err(e) => Err(e),
			}
		});
	}
	for stun_addr in ice_addr.stun {
		rets.spawn(async move {
			match analyze_addr_latency(stun_addr, udp).await {
				Ok(l) => Ok((stun_addr, l)),
				Err(e) => Err(e),
			}
		});
	}
	for map_addr in ice_addr.port_map {
		rets.spawn(async move {
			match analyze_addr_latency(map_addr, udp).await {
				Ok(l) => Ok((map_addr, l)),
				Err(e) => Err(e),
			}
		});
	}
	for static_addr in ice_addr.statics {
		rets.spawn(async move {
			match analyze_addr_latency(static_addr, udp).await {
				Ok(l) => Ok((static_addr, l)),
				Err(e) => Err(e),
			}
		});
	}

	let res = tokio::select! {
		v = rets.join_all() => v,
		_ = cancellation_token.cancelled() => {
			return vec![]
		},
	};
	for x in res.into_iter() {
		if let Ok(addr) = x {
			debug!("addr test: {} latency={:?}", addr.0, addr.1);
			new_ice_addr.push(addr);
		}
	}

	new_ice_addr.sort_by(|(_, al), (_, bl)| al.cmp(bl));

	new_ice_addr.iter().map(|(addr, _)| addr.clone()).collect()
}

fn update_ice_addr(ice_addr: &mut ice::IceAddr, intfs: &Vec<netdev::Interface>, cur_port: u16) {
	let mut ip4list = vec![];
	let mut ip6list = vec![];
	ice_addr.lan = vec![];
	ice_addr.ipv6 = vec![];
	ice_addr.statics = vec![];

	for x in intfs {
		for x in x.ipv4.iter() {
			ip4list.push(x.addr())
		}
		for x in x.ipv6.iter() {
			ip6list.push(x.addr())
		}
	}
	for ip4 in ip4list {
		if ip4.is_private() {
			ice_addr.lan.push(SocketAddr::V4(SocketAddrV4::new(ip4, cur_port)))
		} else {
			ice_addr.statics.push(SocketAddr::V4(SocketAddrV4::new(ip4, cur_port)))
		}
	}
	for ip6 in ip6list {
		if Ipv6AddrC(ip6).is_global() {
			ice_addr.ipv6.push(SocketAddr::V6(SocketAddrV6::new(ip6, cur_port, 0, 0)))
		} else {
			ice_addr.lan.push(SocketAddr::V6(SocketAddrV6::new(ip6, cur_port, 0, 0)))
		}
	}
}

fn test_port_available(port: u16, udp: bool) -> bool {
	if udp {
		std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok() && std::net::UdpSocket::bind(("::", port)).is_ok()
	} else {
		std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() && std::net::TcpListener::bind(("::", port)).is_ok()
	}
}

fn sync_wgintf(
	conf: WgConfShare,
	wgapi_: Arc<Mutex<Option<WgIntf>>>,
	allow_peers: &mut HashMap<String, Peer>,
	ifname: &str,
) {
	let peers: Vec<Peer> = allow_peers.values().cloned().collect();
	let mut wgapi_lock = wgapi_.lock().unwrap();

	if wgapi_lock.is_none() && !peers.is_empty() {
		match wg::WgIntf::new(ifname, &conf.load().wg, Some(peers)) {
			Ok(v) => {
				wgapi_lock.replace(v);
			}
			Err(e) => {
				error!("cannot create wgintf {}", e);
			}
		};
	} else if !peers.is_empty() {
		match wgapi_lock.as_mut().unwrap().sync_config(&conf.load().wg, &peers) {
			Ok(_) => {}
			Err(e) => error!("cannot sync wg config {}", e),
		}
	}
}

// 安全同步状态
// 仅同步`status`到disk, 其他配置从disk 同步到内存
// 注意：同步到内存不代表配置即时更新
fn sync_conf_to_disk(conf_path: &PathBuf, conf: WgConfShare) -> bool {
	let mut need_reload = false;
	if let Ok(v) = config::read_config_file(conf_path) {
		let mut cur_conf = conf.load().copy();

		let skip_dump = v.status != cur_conf.status;

		if cur_conf.wg != v.wg || cur_conf.network != v.network || cur_conf.discovery != v.discovery {
			cur_conf.wg = v.wg;
			cur_conf.network = v.network;
			cur_conf.discovery = v.discovery;
			conf.store(Arc::new(cur_conf));
			need_reload = true;
		}

		if skip_dump {
			debug!("config file already exists and equal of memory, skip save");
			return need_reload;
		}
	};

	let yaml = match serde_yaml::to_string(&conf.load().copy()) {
		Ok(v) => v,
		Err(e) => {
			error!("cannot serde to yaml: {}", e);
			return need_reload;
		}
	};
	match util::safe_write_file(conf_path, yaml) {
		Ok(_) => {},
		Err(e) => error!("cannot write config file {}", e),
	}
	need_reload
}

fn create_bpf_update_info(netid: &[u8; 32], intfs: &Vec<Interface>, wg_port: u16, echo_port: u16) -> UpdateIntfs {
	let intf_ids = intfs.iter().map(|i| i.index).collect::<Vec<_>>();
	let mut ips = Vec::new();

	for intf in intfs.iter() {
		for ip in intf.ipv4.iter() {
			ips.push(ip.addr().into())
		}
		for ip in intf.ipv6.iter() {
			ips.push(ip.addr().into())
		}
	}

	UpdateIntfs {
		netid: netid.clone(),
		ip: Some(ips),
		intfs: Some(intf_ids),
		portmaps: Some(vec![(wg_port, echo_port)]),
		portmaps_out: Some(vec![(echo_port, wg_port)]),
	}
}

// tcp mode:
// wireguard: 51820(udp) echo_server: 51820(tcp)
// udp mode:
// wireguard: 51820(udp) echo_server: 51821(udp)
fn find_avail_wg_port(only_udp: bool, start_port: u16) -> u16 {
	let mut sport = if start_port == 0 {
		config::DEFAULT_WG_PORT
	} else {
		start_port
	};
	if only_udp {
		while !(test_port_available(sport, true) && test_port_available(sport + 1, true)) {
			sport += 1
		}
		sport
	} else {
		while !test_port_available(sport, true) && test_port_available(sport, false) {
			sport += 1
		}
		sport
	}
}

fn sync_peer_to_config(conf: WgConfShare, peer_map: &mut HashMap<String, Peer>) {
	let config = conf.load();

	let mut new_config = None;

	if config.status.is_none() {
		let mut new_conf = config.copy();
		new_conf.status = Some(config::Status { peers: vec![] });
		new_config.replace(new_conf);
	}
	// 添加与更新
	for (key, peer) in peer_map.iter() {
		let old_peer = config.get_peer(key);
		if old_peer.is_none() {
			if new_config.is_none() {
				new_config.replace(config.copy());
			}

			new_config.as_mut().unwrap().add_peer(peer.clone());
			continue;
		}
		let old_peer = old_peer.unwrap();
		if old_peer.eq(peer) {
			continue;
		}
		if new_config.is_none() {
			new_config.replace(config.copy());
		}

		new_config.as_mut().unwrap().replace_peer(peer.clone());
	}
	// 删除
	if let Some(status) = config.status.as_ref() {
		for peer in status.peers.iter() {
			if peer_map.contains_key(&peer.key) {
				continue;
			}
			if new_config.is_none() {
				new_config.replace(config.copy());
			}
			new_config.as_mut().unwrap().remove_peer(&peer.key);
		}
	}

	if let Some(new) = new_config {
		conf.store(Arc::new(new));
	}
}

async fn process_ctrl_msg(
	msg: WgCtrlMsg,
	conf: WgConfShare,
	allow_peers_ref: &mut HashMap<String, Peer>,
	passive_mode: bool,
	netname: &str,
	mq_connect: &mut MqConnect,
	all_known_peers: &mut HashSet<String>,
	event_tx: Sender<WgCtrlMsg>,
	self_pubkey: &String,
	wgapi: Arc<Mutex<Option<WgIntf>>>,
	ifname: &String,
	cur_ice_addr_ref: &mut IceAddr,
	network_cancel: CancellationToken,
) {
	match msg {
		WgCtrlMsg::AddPeer { wg, mut endpoint } => {
			debug!(
				"network: {} add peer {} {}",
				netname,
				wg.name.clone().unwrap(),
				wg.public
			);
			if passive_mode {
				endpoint = None;
			}
			let peer = config::Peer {
				key: (&wg.public).clone(),
				name: wg.name,
				endpoint,
				allow_ips: wg.ip,
			};
			
			allow_peers_ref.insert(wg.public.clone(), peer);
			sync_peer_to_config(conf.clone(), allow_peers_ref);
			sync_wgintf(conf.clone(), wgapi, allow_peers_ref, &ifname);
		}
		WgCtrlMsg::RemovePeer { pubkey } => {
			let peer = allow_peers_ref.remove(&pubkey);
			if peer.is_some() {
				sync_peer_to_config(conf.clone(), allow_peers_ref);
			}
			sync_wgintf(conf.clone(), wgapi, allow_peers_ref, &ifname);
			info!("remove peer {}", pubkey);
		}
		WgCtrlMsg::UpdatePeer {
			wg,
			endpoints,
			traceroute,
		} => {
			debug!(
				"network: {} update peer \"{}\" {:?} {:?}",
				netname,
				wg.name.as_ref().unwrap_or(&wg.public),
				endpoints,
				wg.ip
			);
			if wg.public.eq(self_pubkey) {
				return;
			}
			if passive_mode {
				debug!("node is passive mode, ignore peer update");
			}

			let mut need_sync = false;
			let mut fallback_stun = None;
			let mut endpoint = None;
			if let Some(endpoint_addrs) = endpoints {
				if !endpoint_addrs.stun.is_empty() {
					// 当peer 在nat 后且所有endpoint 都测试失败时, 使用stun地址作为最后手段,并期待stun映射能恢复 
					fallback_stun = Some(endpoint_addrs.stun[0].clone());
				}
				let available_addrs = analyze_ice_addrs(endpoint_addrs, network_cancel.clone()).await;
				if !available_addrs.is_empty() {
					endpoint = Some(available_addrs[0]);
				} else if fallback_stun.is_some() {
					endpoint = fallback_stun;
				}
			}
			if let Some(p) = allow_peers_ref.get_mut(&wg.public) {
				p.allow_ips = wg.ip;
				if endpoint.is_some() && p.endpoint != endpoint {
					'bar1: {
						if wgapi.lock().unwrap().is_none() {
							break 'bar1;
						}
						let host_peer = {
							let wgapi_lock = wgapi.lock().unwrap();
							let api = wgapi_lock.as_ref().unwrap();
							api.get_peer(&p.key)
						};
						if host_peer.is_none() {
							break 'bar1;
						}
						let host_peer = host_peer.unwrap();
						if host_peer.endpoint.is_none() || host_peer.last_handshake.is_none() {
							break 'bar1;
						}
						let last_handshake = host_peer.last_handshake.unwrap();
						let last_endpoint = host_peer.endpoint.unwrap();

						if let Ok(d) = last_handshake.elapsed() {
							if d < Duration::from_secs(20) {
								endpoint = Some(last_endpoint);
							}
						}
					}

					if p.endpoint != endpoint {
						p.endpoint = endpoint;
						info!(
							"update peer {}({}) endpoint to {:?}",
							&p.name.as_ref().unwrap_or(&"<none>".to_string()),
							p.key,
							endpoint
						);
						need_sync = true;
					}
				}
				// debug!("network: {} update peer: {:?}", netname, p);
			} else {
				event_tx.send(WgCtrlMsg::AddPeer { wg, endpoint }).await.unwrap();
				return;
			}
			if need_sync {
				sync_wgintf(conf.clone(), wgapi, allow_peers_ref, &ifname);
				sync_peer_to_config(conf.clone(), allow_peers_ref);
			}
		}
		WgCtrlMsg::PubipChanged { ips: _ } => {
			// todo: remap nat and push update msg

			mq_connect
				.sendmsg(MqMsg {
					t: MqMsgType::Update(mq_msg::MsgUpdate {
						wg: conf.load().wg.clone_to_share(),
						endpoints: cur_ice_addr_ref.clone(),
						traceroute: None,
					}),
					salt: None,
				})
				.await
				.unwrap();
		}
		WgCtrlMsg::Announce { wg } => {
			if wg.public.eq(self_pubkey) {
				return;
			}
			if allow_peers_ref.contains_key(&wg.public) {
				mq_connect
					.sendmsg(MqMsg {
						t: MqMsgType::Update(mq_msg::MsgUpdate {
							wg: conf.load().wg.clone_to_share(),
							endpoints: cur_ice_addr_ref.clone(),
							traceroute: None,
						}),
						salt: None,
					})
					.await
					.unwrap();
				return;
			}
			all_known_peers.insert(wg.public.clone());
			event_tx.send(WgCtrlMsg::AddPeer { wg, endpoint: None }).await.unwrap()
		}
	}
}

async fn wg_config_loop(
	conf_path: PathBuf,
	wg_config: WgConfig,
	portmap_tx: sync::mpsc::Sender<portmap::MapAction>,
	network_cancel: CancellationToken,
	mut sender: Option<Sender<UpdateIntfs>>,
	reload_tx: Sender<(PathBuf, WgConfig)>,
) {
	let netname = wg_config.network.name.clone();
	// Create new API struct for interface
	let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
		format!("wg{}", netname)
	} else {
		format!("utun{}", netname)
	};
	let mut need_reload = false;

	let mut interval = tokio::time::interval(Duration::from_secs(wg_config.discovery.interval.unwrap_or(120)));

	let (event_tx, mut event_rx) = sync::mpsc::channel::<WgCtrlMsg>(10);

	let network_policy = wg_config.network.interface_policy.clone().unwrap_or_default();

	let wgapi: Arc<Mutex<Option<WgIntf>>> = Arc::new(Mutex::new(None));

	let self_pubkey = wg_config.wg.public.clone();
	let network_id = util::keystr_to_array(&wg_config.network.id).unwrap();

	let bpf_sender = sender.as_mut();
	let support_udp_mode = bpf_sender.is_some();
	let passive_mode = wg_config.discovery.passive.unwrap_or(false);
	let mut cur_port = wg_config.wg.port;

	let conf = Arc::new(arc_swap::ArcSwap::from_pointee(wg_config));
	// let mut prev_pubip_v4 = vec![];
	// let mut prev_pubip_v6 = vec![];
	// let mut prev_nat_type = None;

	let mut cur_ice_addr = IceAddr::default();
	let cur_ice_addr_ref = &mut cur_ice_addr;

	let mut all_known_peers = HashSet::new();
	let mut allow_peers = HashMap::new();
	let allow_peers_ref = &mut allow_peers;

	cur_port = find_avail_wg_port(support_udp_mode, cur_port);

	let intfs = util::filter_avail_interface(&network_policy);

	let mut mq_connect = MqConnect::new(conf.load_full().copy()).await.expect("cannot connect to mq");

	{
		let config = conf.load();
		if let Some(status_ref) = config.status.as_ref() {
			for peer in status_ref.peers.iter() {
				allow_peers_ref.insert(peer.key.clone(), peer.clone());
			}
		}
	}
	let echo_server = if support_udp_mode {
		EchoServer::new(cur_port + 1, 0).await.expect("cannot create echo server")
	} else {
		EchoServer::new(0, cur_port).await.expect("cannot create echo server")
	};

	cur_ice_addr_ref.support_udp = support_udp_mode;
	let udp_sock4 = echo_server.get_udp_sock();

	let stun_udp_sock = if udp_sock4.is_some() {
		Some((udp_sock4.as_ref().unwrap(), cur_port + 1))
	} else {
		None
	};
	if support_udp_mode {
		let ret = bpf_sender
			.as_ref()
			.unwrap()
			.send(create_bpf_update_info(&network_id, &intfs, cur_port, cur_port + 1))
			.await;
		if ret.is_err() {
			error!("cannot send bpf_updateinfo to bpf_sender: {}", ret.unwrap_err());
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	let (mut pubaddr, mut nat_type) = stun_do_trans(
		SocketAddr::new(IPADDRV4_UNSPECIFIED, cur_port),
		conf.load().discovery.stuns.clone(),
		stun_udp_sock,
	)
	.await
	.unwrap_or((vec![], stun::StunType::Blocked));
	debug!("probe stun for default {:?} {:?}", pubaddr, nat_type);
	if nat_type != stun::StunType::Blocked && nat_type != stun::StunType::Symmetric {
		cur_ice_addr_ref.stun = pubaddr;
	}

	update_ice_addr(cur_ice_addr_ref, &intfs, cur_port);

	let _ = mq_connect
		.sendmsg(mq_msg::MqMsg {
			t: mq_msg::MqMsgType::Announce(mq_msg::MsgAnnounce {
				wg: conf.load().wg.clone_to_share(),
			}),
			salt: None,
		})
		.await;
	let mut udp_recv_buf = Box::new([0u8; 16384]);

	let udp_cancel = network_cancel.clone();
	let tcp_cancel = network_cancel.clone();
	let mqtt_cancel = network_cancel.clone();

	sync_wgintf(conf.clone(), wgapi.clone(), allow_peers_ref, &ifname);

	loop {
		tokio::select! {
			_ = network_cancel.cancelled() => {
				info!("network {} recv canceled", netname);
				break;
			},
			_ = interval.tick() => {
				info!("start tick");
				let intfs = util::filter_avail_interface(&network_policy);
				if !intfs.is_empty() {
					sync_wgintf(conf.clone(), wgapi.clone(), allow_peers_ref, &ifname);
					debug!("get interface: {:?}", intfs);
					update_ice_addr(cur_ice_addr_ref, &intfs, cur_port);
					if support_udp_mode {
						let ret = bpf_sender.as_ref().unwrap().send(create_bpf_update_info(&network_id, &intfs, cur_port, cur_port + 1)).await;
						if ret.is_err() {
							error!("cannot send bpf_updateinfo to bpf_sender: {}", ret.unwrap_err());
						}
					}

					(pubaddr, nat_type) = stun_do_trans(SOCKETADDRV4_UNSPECIFIED,
							conf.load().discovery.stuns.clone(),
							stun_udp_sock
						).await
						.unwrap_or((vec![], stun::StunType::Blocked));
					if nat_type != stun::StunType::Blocked && nat_type != stun::StunType::Symmetric {
						cur_ice_addr_ref.stun = pubaddr;
					}
					// let mut pubips_v4 = get_pubip_list(&conf.load().discovery.pubip, true, &intfs[0].name).await.unwrap_or_else(|_| {vec![]});
					// let pubips_v6 = get_pubip_list(&conf.load().discovery.pubip, false, &intfs[0].name).await.unwrap_or_else(|_| {vec![]});
					// if prev_pubip_v4 != pubips_v4 || prev_pubip_v6 != pubips_v6 || prev_nat_type != Some(nat_type) {
					// 	prev_pubip_v4 = pubips_v4.clone();
					// 	prev_pubip_v6 = pubips_v6.clone();
					// 	prev_nat_type = Some(nat_type);
					// 	pubips_v4.extend(&pubips_v6);
					// 	let _ = event_tx.send(WgCtrlMsg::PubipChanged { ips:  pubips_v4}).await;
					// }

					// portmap_tx.send(portmap::MapAction::Map {})

					let _ = mq_connect.sendmsg(MqMsg {
								t: MqMsgType::Update(mq_msg::MsgUpdate {
									wg: conf.load().wg.clone_to_share(),
									endpoints: cur_ice_addr_ref.clone(),
									traceroute: None,
								}),
								salt: None
								}).await;
					need_reload = sync_conf_to_disk(&conf_path, conf.clone());
					if need_reload {
						break;
					}
				}else {
					warn!("network {} not found available interface, skip wireguard interface setup", netname);
				}
			},
			_ = echo_server.start_udp_echo(&udp_cancel, &mut udp_recv_buf) => {},
			_ = echo_server.start_tcp_echo(&tcp_cancel) => {},
			msg = event_rx.recv() => {
				if msg.is_none() {
					break;
				}
				let msg = msg.unwrap();
				// debug!("network: {} recv ctrl msg {:?}", netname, msg);
				process_ctrl_msg(msg, conf.clone(), allow_peers_ref, passive_mode, &netname,
					&mut mq_connect, &mut all_known_peers, event_tx.clone(),
					&self_pubkey,
					wgapi.clone(),
					&ifname,
					cur_ice_addr_ref,
					network_cancel.clone()
				).await;
			},
			msg = mq_connect.recvmsg(&mqtt_cancel) => {
				if msg.is_none() {
					continue;
				}
				event_tx.send(msg.unwrap()).await.unwrap()
			},
		}
	}

	if support_udp_mode {
		let ret = bpf_sender
			.as_ref()
			.unwrap()
			.send(UpdateIntfs {
				netid: network_id,
				..Default::default()
			})
			.await;
		if ret.is_err() {
			error!("cannot send delete bpf_update_info to bpf_sender: {}", ret.unwrap_err());
		}
	}
	sync_peer_to_config(conf.clone(), allow_peers_ref);
	sync_conf_to_disk(&conf_path, conf.clone());

	{
		let wgapi_lock = wgapi.lock().unwrap();
		if let Some(wgapi_) = wgapi_lock.as_ref() {
			let _ = wgapi_.remove();
			info!("interface {} removed", ifname);
		}
	}
	drop(mq_connect);
	drop(echo_server);
	if need_reload {
		let _ = reload_tx.send((conf_path, conf.load().copy())).await;
	};
}

async fn network_loop(
	portmap_tx: sync::mpsc::Sender<portmap::MapAction>,
	mut rx: sync::mpsc::Receiver<NetworkMessage>,
	main_cancel: CancellationToken,
	sender: Option<Sender<UpdateIntfs>>,
) {
	let set = tokio_util::task::TaskTracker::new();
	let all_network_cancel = main_cancel.child_token();
	
	let mut network_cancel = HashMap::new();
	
	let (reload_tx, mut reload_rx) = sync::mpsc::channel(10);
	loop {
		tokio::select! {
			msg = rx.recv() => {
				match msg {
					Some(NetworkMessage::Add((conf_path, conf))) => {
						info!("start network {}", conf.network.name);
						let child = all_network_cancel.child_token();
						let id = conf.network.id.clone();
						network_cancel.insert(id, child.clone());
						set.spawn(wg_config_loop(conf_path, conf, portmap_tx.clone(), child, sender.clone(), reload_tx.clone()));
					},
					Some(NetworkMessage::Leave((_, conf))) => {
						info!("leave network {}", conf.network.name);
						let token = network_cancel.remove(&conf.network.id);
						if let Some(cancel) = token {
							cancel.cancel();
						}
					},
					None => break,
				}
			},
			res = reload_rx.recv() => {
				if res.is_none() {
					break;
				}
				let (conf_path, conf): (_, _) = res.unwrap();
				info!("reload network {}", conf.network.name);
				
				if let Some(cancel) = network_cancel.remove(&conf.network.id) {
					cancel.cancel();
				}
				
				let child = all_network_cancel.child_token();
				let id = conf.network.id.clone();
				network_cancel.insert(id, child.clone());
				set.spawn(wg_config_loop(conf_path, conf, portmap_tx.clone(), child, sender.clone(), reload_tx.clone()));
				
			},
			_ = main_cancel.cancelled() => {
				all_network_cancel.cancel();
				break;
			}
		}
	}

	set.close();
	if let Err(_) = tokio::time::timeout(
		Duration::from_secs(10),
		set.wait()
	).await {
		error!("close network loop timed out");
	};
	
}
async fn config_monitor(
	config_dir: impl AsRef<Path>,
	network_tx: sync::mpsc::Sender<NetworkMessage>,
	main_cancel: CancellationToken,
) {
	let mut prev_configs: HashMap<PathBuf, WgConfig> = HashMap::new();
	let mut prev_configs_values = vec![];
	let mut interval = tokio::time::interval(time::Duration::from_secs(5));
	loop {
		tokio::select! {
			_ = main_cancel.cancelled() => {
				break;
			}
			_ = interval.tick() => {
				let new_configs = config::load_all_net_map(&config_dir);
				let new_configs_values:Vec<_> = new_configs.clone().into_iter().map(|x| x.1).collect();

				let del:Vec<_> = prev_configs.clone().into_iter().filter(|(_, item)|!new_configs_values.contains(item)).collect();
				let add: Vec<_> = new_configs.clone().into_iter().filter(|(_, item)| !prev_configs_values.contains(item)).collect();

				for conf in del {
					let _ = network_tx.send(NetworkMessage::Leave(conf)).await;
				}
				for conf in add {
					let _ = network_tx.send(NetworkMessage::Add(conf)).await;
				}
				prev_configs = new_configs;
				prev_configs_values = new_configs_values;
			},
		}
	}
}

pub fn start_daemon(config_dir: impl AsRef<Path> + Send + 'static) {
	println!("Starting daemon");

	let (network_tx, network_rx) = sync::mpsc::channel(1);
	let (portmap_tx, portmap_rx) = sync::mpsc::channel(1);
	tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_io()
		.enable_time()
		.build()
		.unwrap()
		.block_on(async move {
			let main_token = CancellationToken::new();

			let (tx, rx) = tokio::sync::mpsc::channel(1);
			let (ok_tx, ok_rx) = tokio::sync::oneshot::channel();
			let bpf_handle = tokio::task::spawn(bpf_instance::bpf_event_loop(main_token.clone(), rx, ok_tx));
			let sender;
			tokio::select! {
				bpf_result = bpf_handle => {
					error!("cannot load bpf :{}", bpf_result.unwrap_err());
					sender = None;
				},
				_ = ok_rx => {
					sender = Some(tx);
				}
			}

			let mut set = tokio::task::JoinSet::new();

			set.spawn(network_loop(portmap_tx, network_rx, main_token.clone(), sender));
			set.spawn(config_monitor(config_dir, network_tx, main_token.clone()));
			set.spawn(portmap_loop(portmap_rx, main_token.clone()));

			wait_for_signal().await;
			main_token.cancel();
			if let Err(_) = tokio::time::timeout(
				Duration::from_secs(10),
				set.join_all()
			).await {
				error!("close main loop timed out");
			};
		});
}

/// Waits for a signal that requests a graceful shutdown, like SIGTERM or SIGINT.
#[cfg(unix)]
async fn wait_for_signal_impl() {
	use tokio::signal::unix::{SignalKind, signal};

	// Infos here:
	// https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
	let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
	let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

	tokio::select! {
		_ = signal_terminate.recv() => debug!("Received SIGTERM."),
		_ = signal_interrupt.recv() => debug!("Received SIGINT."),
	};
}

/// Waits for a signal that requests a graceful shutdown, Ctrl-C (SIGINT).
#[cfg(windows)]
async fn wait_for_signal_impl() {
	use tokio::signal::windows;

	// Infos here:
	// https://learn.microsoft.com/en-us/windows/console/handlerroutine
	let mut signal_c = windows::ctrl_c().unwrap();
	let mut signal_break = windows::ctrl_break().unwrap();
	let mut signal_close = windows::ctrl_close().unwrap();
	let mut signal_shutdown = windows::ctrl_shutdown().unwrap();

	tokio::select! {
		_ = signal_c.recv() => debug!("Received CTRL_C."),
		_ = signal_break.recv() => debug!("Received CTRL_BREAK."),
		_ = signal_close.recv() => debug!("Received CTRL_CLOSE."),
		_ = signal_shutdown.recv() => debug!("Received CTRL_SHUTDOWN."),
	};
}

/// Registers signal handlers and waits for a signal that
/// indicates a shutdown request.
pub(crate) async fn wait_for_signal() {
	wait_for_signal_impl().await
}

#[cfg(test)]
mod tests {
	use crate::daemon::test_port_available;
	use rumqttc::{MqttOptions, Transport};
	use std::time::Duration;
	use url;

	#[test]
	fn test_test_port_available() {
		assert!(test_port_available(0, true));
		assert!(test_port_available(0, false));
	}
}
