use crate::config::Pubip;
use log::{error, warn};
use regex::Regex;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

async fn get_ip_server(ip: &Pubip, ipv4: bool, client: &reqwest::Client) -> io::Result<IpAddr> {
	let mut reg: Option<Regex> = None;
	if let Some(re) = ip.regex.clone() {
		match regex::Regex::new(&re) {
			Ok(v) => reg = Some(v),
			Err(e) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!("cannot compile regex: {}", e.to_string()),
				));
			}
		};
	}

	let resp = match client.get(ip.url.clone()).send().await {
		Ok(p) => p,
		Err(e) => {
			warn!("cannot get ip from {}: {}", ip.url, e);
			return Err(io::Error::new(io::ErrorKind::Other, "cannot get ip"));
		}
	};

	let body = match resp.text().await {
		Ok(b) => b,
		Err(e) => {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "cannot parse body to text"));
		}
	};

	let ip_str;
	if let Some(re) = reg {
		let find = re.find(&body);
		if find.is_none() {
			error!("cannot find ip from {:?} with {}", body, re.as_str());
			return Err(io::Error::new(io::ErrorKind::InvalidData, "cannot match ip from body"));
		}
		let find = find.unwrap();
		ip_str = find.as_str().to_string();
	} else {
		ip_str = body;
	}

	match IpAddr::from_str(&ip_str) {
		Ok(ip) => Ok(ip),
		Err(e) => {
			error!("cannot parse ip from {}", ip_str);
			Err(io::Error::new(io::ErrorKind::InvalidData, "cannot parse ip from body"))
		}
	}
}

pub(crate) async fn get_pubip_list(ips: &Vec<Pubip>, ipv4: bool, intf: &str) -> io::Result<Vec<IpAddr>> {
	let client = match reqwest::ClientBuilder::new()
		.connect_timeout(Duration::from_secs(5))
		.user_agent("curl/7.68.0")
		.interface(intf)
		.local_address({
			if ipv4 {
				Some(IpAddr::from(Ipv4Addr::UNSPECIFIED))
			} else {
				Some(IpAddr::from(Ipv6Addr::UNSPECIFIED))
			}
		})
		.build()
	{
		Ok(c) => c,
		Err(e) => {
			error!("cannot build http client {}", e);
			return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
		}
	};

	let mut pubips = vec![];
	for ip in ips {
		match get_ip_server(ip, ipv4, &client).await {
			Ok(p) => pubips.push(p),
			Err(e) => {
				warn!("cannot get public ip from {:?}: {}", ip, e);
			}
		}
	}
	pubips.sort();
	pubips.dedup();
	Ok(pubips)
}
