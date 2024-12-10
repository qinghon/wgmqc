use crate::config::Wg;
use crate::ice::IceAddr;
use crate::util;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use x25519_dalek::StaticSecret;
use xeddsa::Verify;

#[derive(Debug, Serialize, Deserialize)]
struct AdminSign {
	/// public key for wireguard
	key: [u8; 32],
	// start time and end time , like tls
	start: u64,
	end: u64,
}
#[derive(Debug, Serialize, Deserialize)]
struct SignData {
	sign: Vec<u8>,
	data: AdminSign,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum MqMsgType {
	Sign(MsgSign),
	Announce(MsgAnnounce),
	Update(MsgUpdate),
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MqMsg {
	pub(crate) t: MqMsgType,
	// #[serde(rename = "salt")]
	pub(crate) salt: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SignMsgWg {
	#[serde(rename = "public")]
	public: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MsgSign {
	wg: SignMsgWg,
	sign_data: SignData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Internal {
	#[serde(rename = "ip")]
	ip: IpAddr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Traceroute {
	#[serde(rename = "pubip")]
	pubip: String,

	#[serde(rename = "routes")]
	routes: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MsgUpdate {
	#[serde(rename = "wg")]
	pub(crate) wg: Wg,

	#[serde(rename = "endpoints")]
	pub(crate) endpoints: IceAddr,

	#[serde(rename = "traceroute")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(crate) traceroute: Option<Vec<Traceroute>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MsgAnnounce {
	pub(crate) wg: Wg,
}
impl MqMsg {
	pub(crate) fn is_admin(&self) -> bool {
		match self.t {
			MqMsgType::Sign(_) => true,
			MqMsgType::Announce(_) => false,
			MqMsgType::Update(_) => false,
		}
	}
	pub(crate) fn sign_data(&mut self, prikey: &StaticSecret) {
		if self.salt.is_some() {
			return;
		}
		let data_json = serde_json::to_string(&self.t).unwrap();

		let pk = xeddsa::xed25519::PrivateKey::from(prikey.as_bytes());
		// use xeddsa::*;
		use xeddsa::xeddsa::Sign;
		let rng = rand::thread_rng();
		let sign_data: ed25519::Signature = pk.sign(data_json.as_bytes(), rng);
		let d = base64::prelude::BASE64_STANDARD.encode(sign_data.to_vec());
		self.salt = Some(d);
	}
	pub(crate) fn verify_data(&self, admin_pubkey: Option<String>) -> bool {
		let pubkey_b64 = match &self.t {
			MqMsgType::Sign(_) => admin_pubkey.unwrap().clone(),
			MqMsgType::Announce(v) => v.wg.public.clone(),
			MqMsgType::Update(v) => v.wg.public.clone(),
		};
		if self.salt.is_none() || self.salt.as_ref().unwrap().len() != 64 {
			return false;
		}
		let mut salt: [u8; 64] = [0; 64];
		match base64::prelude::BASE64_STANDARD.decode_slice(&self.salt.as_ref().unwrap(), &mut salt) {
			Ok(_) => {}
			Err(_) => return false,
		}
		// salt.copy_from_slice(&self.salt.clone().unwrap());

		// let salt = self.salt.clone().unwrap();
		let pubkey_array = match util::keystr_to_array(&pubkey_b64) {
			None => return false,
			Some(v) => v,
		};
		let data_json = serde_json::to_string(&self.t).unwrap();

		let pubkey = xeddsa::xed25519::PublicKey::from(&x25519_dalek::PublicKey::from(pubkey_array));

		pubkey.verify(data_json.as_bytes(), &salt).is_ok()
	}
	pub(crate) fn from_slice(v: &[u8]) -> Result<Self, std::io::Error> {
		let d: Self = serde_json::from_slice(v)?;
		Ok(d)
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	use base64::Engine;
	#[test]
	fn test_verify_sign() {
		let alice_secret = StaticSecret::random();
		let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
		let mut mq = MqMsg {
			t: MqMsgType::Sign(MsgSign {
				wg: SignMsgWg { public: "".to_string() },
				sign_data: SignData {
					sign: vec![],
					data: AdminSign {
						key: [0; 32],
						start: 0,
						end: 0,
					},
				},
			}),
			salt: None,
		};

		mq.sign_data(&alice_secret);

		assert!(mq.verify_data(Some(base64::prelude::BASE64_STANDARD.encode(alice_public.to_bytes()))));
	}
	fn test_mq_msg_verify() {
		let alice_secret = StaticSecret::random();
		let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
		let mut mq = MqMsg {
			t: MqMsgType::Announce(MsgAnnounce { wg: Wg::random_new() }),
			salt: None,
		};

		mq.sign_data(&alice_secret);
		assert!(mq.verify_data(None));
	}
}
