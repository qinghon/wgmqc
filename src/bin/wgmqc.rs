use base64::Engine;
use clap::{Args, Parser, Subcommand};
use log::{debug, error};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
// use wgmqc::config::{Network, WgConfig};
use wgmqc::*;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
	/// Sets a custom config file
	#[arg(short, long, value_name = "config_dir")]
	config_dir: Option<PathBuf>,

	/// Turn debugging information on
	#[arg(long)]
	log_level: Option<u8>,

	#[command(subcommand)]
	command: SubCmd,
}

#[derive(Debug, Subcommand)]
enum SubCmd {
	/// does testing things
	Daemon,
	Network(SubNet),
	Peer(SubPeer),
	Stun {
		#[arg(long)]
		port: Option<u16>,

		#[arg(long)]
		stun_server: Option<Vec<String>>,
	},
}

#[derive(Debug, Args)]
struct SubNet {
	#[command(subcommand)]
	command: SubNetCmd,
}
#[derive(Debug, Subcommand)]
enum SubNetCmd {
	List {
		#[arg(long, default_value_t = false)]
		verbose: bool,
	},
	Create {
		name: String,
		#[arg(long)]
		desc: Option<String>,
		broker: String,
		#[arg(long)]
		mq_user: Option<String>,
		#[arg(long)]
		mq_password: Option<String>,
		#[arg(long)]
		#[clap(value_enum)]
		allow_policy: Option<config::AllowPolicy>,
		#[arg(long)]
		update_interval: Option<usize>,
		#[arg(help = "ip and network for net, the ip is self peer first default ip")]
		ip_cidr: String,

		// ip for peer
		#[arg(long)]
		peer_name: Option<String>,
		#[arg(long)]
		peer_ip: Vec<ipnet::IpNet>,
	},
	Share {
		net: Option<String>,
		#[arg(long, help = "export admin permission key")]
		admin: Option<bool>,
	},
	Join {
		config: String,
		// ip for peer
		#[arg(long)]
		peer_name: Option<String>,
		#[arg(long)]
		peer_ip: Vec<ipnet::IpNet>,
	},
	Leave {
		net: Option<String>,
		#[arg(long)]
		confirm: bool,
	},
	Update {
		net: Option<String>,
	},
}
#[derive(Debug, Args)]
struct SubPeer {
	#[command(subcommand)]
	command: SubPeerCmd,
}
#[derive(Debug, Subcommand)]
enum SubPeerCmd {
	List { net: Option<String> },
	Allow { net: Option<String>, key: String },
	Deny { net: Option<String>, key: String },
}

fn main() {
	// The `Env` lets us tweak what the environment
	// variables to read are and what the default
	// value is if they're missing
	let env = env_logger::Env::default()
		.filter_or("WG_LOG_LEVEL", "info")
		.write_style_or("WG_LOG_STYLE", "SYSTEMD");
	env_logger::init_from_env(env);

	let args = Cli::parse();

	debug!("{:?}", args);
	let config_dir = args.config_dir.unwrap_or(PathBuf::from("/etc/wgmqc"));

	match args.command {
		SubCmd::Daemon => daemon::start_daemon(config_dir),
		SubCmd::Network(subnet) => subcmd_subnet(config_dir, subnet),
		SubCmd::Peer(p) => subcmd_subpeer(config_dir, p),
		SubCmd::Stun { port, stun_server } => stun::do_stun_test(port, stun_server),
	}
}

fn subcmd_subnet(config_dir: PathBuf, subnet: SubNet) {
	match subnet.command {
		SubNetCmd::List { verbose } => {
			let nets = config::load_all_net(&config_dir);
			subcmd_net_list(nets, verbose);
		}
		SubNetCmd::Create {
			name,
			desc,
			broker,
			mq_user,
			mq_password,
			allow_policy,
			update_interval,
			ip_cidr,
			peer_name,
			peer_ip,
		} => {
			let net_file = format!("{}.yaml", name);
			let abs_net_file = config_dir.join(net_file);
			if abs_net_file.is_file() && fs::metadata(&abs_net_file).unwrap().st_size() != 0 {
				error!("network config exist!, exiting");
				std::process::exit(17);
			}
			let (pubkey, prikey) = util::new_key_pair();
			let peer_new_name = peer_name_get(peer_name);
			let mut config = config::WgConfig::default();

			config.network.broker = broker;
			config.network.broker_admin_prikey = Some(prikey);
			config.network.broker_admin_pubkey = Some(pubkey);
			config.network.id = config.network.broker_admin_pubkey.clone().unwrap();
			config.network.name = name.clone();
			config.network.desc = desc;
			config.network.mq_user = mq_user;
			config.network.mq_password = mq_password;
			config.network.allow_policy = allow_policy;
			config.network.update_interval = update_interval;

			config.wg = config::Wg::random_new();
			config.wg.name = peer_new_name;
			config.wg.ip = peer_ip;

			let yaml = serde_yaml::to_string(&config).expect("cannot serde to yaml");
			if !config_dir.exists() {
				fs::create_dir_all(config_dir).expect("cannot create config dir");
			}

			fs::write(abs_net_file, yaml).expect("cannot write network");
		}
		SubNetCmd::Share { net, admin } => {
			let nets = config::load_all_net(&config_dir);

			let dump = match (net, nets.len()) {
				(None, 1) => Some(&nets[0]),
				(None, 0) => {
					error!("cannot found any network, please use `network create` to create one");
					std::process::exit(17);
				}
				(Some(net), _) => {
					let net = nets.iter().find(|n| n.network.name == net.clone());
					net
				}
				_ => None,
			};
			if dump.is_none() {
				error!("cannot get network config");
				std::process::exit(17);
			}
			let mut conf = dump.clone().unwrap().network.clone();
			if !admin.unwrap_or(false) {
				conf.broker_admin_prikey = None;
			}
			// is id
			conf.broker_admin_pubkey = None;
			conf.interface_policy = None;
			conf.send_internal = None;
			conf.deny = None;
			debug!("dump yaml: \n{:?}", conf);

			let dump_yaml = serde_yaml::to_string(&conf).expect("cannot serde to yaml");
			let s = base64::prelude::BASE64_STANDARD.encode(dump_yaml);
			println!("{}", s);
		}
		SubNetCmd::Join {
			config,
			peer_name,
			peer_ip,
		} => {
			let net_yaml = base64::prelude::BASE64_STANDARD.decode(config.clone()).expect("cannot decode config");
			let conf: config::Network = serde_yaml::from_slice(&net_yaml).expect("cannot serde from yaml");
			debug!("load yaml: \n{:?}", conf);

			let peer_new_name = peer_name_get(peer_name);

			let mut wg_conf = config::WgConfig {
				network: conf,
				..Default::default()
			};
			wg_conf.network.broker_admin_pubkey = Some(wg_conf.network.id.clone());
			wg_conf.wg = config::Wg::random_new();
			wg_conf.wg.name = peer_new_name;
			wg_conf.wg.ip = peer_ip;

			let nets = config::load_all_net(&config_dir);

			if nets.iter().any(|n| n.network.id == wg_conf.network.id) {
				error!("network id already exists");
				std::process::exit(17);
			}
			let yaml = serde_yaml::to_string(&wg_conf).expect("cannot serde to yaml");
			if !config_dir.exists() {
				fs::create_dir_all(config_dir.clone()).expect("cannot create config dir");
			}
			let net_file = format!("{}.yaml", wg_conf.network.name);
			let abs_net_file = config_dir.join(net_file);
			util::safe_write_file(abs_net_file, yaml).expect("cannot write network config");
		}
		SubNetCmd::Leave { net, confirm } => {
			let nets = config::load_all_net_map(&config_dir);
			match (net, nets.len()) {
				(_, 0) => {
					error!("no network to leave");
					std::process::exit(17);
				}
				(None, 1) => {
					if let Some((path, _)) = nets.into_iter().next() {
						if !confirm {
							error!("please use --confirm to leave the network");
							std::process::exit(17);
						}
						fs::remove_file(path).expect("cannot remove network config");
						std::process::exit(0);
					}
				}
				(None, _) => {
					error!("please specify the network to leave");
					std::process::exit(22);
				}
				(Some(net), _) => {
					for (path, conf) in nets.into_iter() {
						if conf.network.name == net.clone() {
							if !confirm {
								error!("please use --confirm to leave the network");
								std::process::exit(17);
							}
							fs::remove_file(path).expect("cannot remove network config");
							std::process::exit(0);
						}
					}
				}
			}
		}
		SubNetCmd::Update { .. } => {}
	}
}

fn subcmd_net_list(nets: Vec<config::WgConfig>, verbose: bool) {
	if nets.is_empty() {
		return;
	}
	if !verbose {
		println!(
			"{0: <10} | {1: <44} | {2: <32} | {3: <10}",
			"name", "id", "broker", "policy"
		);
		for net in &nets {
			println!(
				"{0: <10} | {1: <44} | {2: <32} | {3: <10}",
				net.network.name,
				net.network.id,
				net.network.broker,
				net.network.allow_policy.unwrap_or(config::AllowPolicy::Public)
			)
		}
	}
}

fn subcmd_subpeer(config_dir: PathBuf, sub_peer: SubPeer) {
	match sub_peer.command {
		SubPeerCmd::List { net } => {
			let nets = config::load_all_net(&config_dir);
			let print_nets;
			match (nets.is_empty(), net.is_none()) {
				(true, true) => return,
				(true, false) => {
					error!("no network find for \"{}\"", net.unwrap());
					std::process::exit(17);
				}
				(false, true) => {
					print_nets = &nets[0..nets.len()];
				}
				(false, false) => {
					let pos = nets.iter().position(|n| n.network.name.eq(net.as_ref().unwrap()));
					if pos.is_none() {
						error!("no network find for \"{}\"", net.unwrap());
						std::process::exit(17);
					}
					let pos = pos.unwrap();
					print_nets = &nets[pos..pos];
				}
			}
			println!("net\tpeer\tendpoint\tip");
			for pnet in print_nets {
				if pnet.status.is_none() {
					println!("{}\t<none>\t<none>\t<none>", pnet.network.name);
					continue;
				}
				for peer in pnet.status.as_ref().unwrap().peers.iter() {
					println!(
						"{}\t{}\t{}\t{:?}",
						pnet.network.name,
						peer.name.as_ref().unwrap_or(&peer.key.clone()),
						peer.endpoint.unwrap_or(util::SOCKETADDRV4_UNSPECIFIED),
						peer.allow_ips
					);
				}
			}
		}
		SubPeerCmd::Allow { .. } => {}
		SubPeerCmd::Deny { .. } => {}
	}
}

fn peer_name_get(setname: Option<String>) -> Option<String> {
	if setname.is_some() {
		return setname;
	}
	if let Ok(name) = hostname::get() {
		if let Ok(s) = name.into_string() {
			return Some(s);
		} else {
			return None;
		}
	}
	None
}
