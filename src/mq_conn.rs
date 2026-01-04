use std::io;
use std::io::ErrorKind;
use std::time::{Duration, Instant};
use rumqttc::{MqttOptions, Transport};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use crate::config::WgConfig;
use crate::{mq_msg, util, Error};
use crate::daemon::WgCtrlMsg;
use crate::mq_msg::{MqMsg, MqMsgType};

pub(crate) struct MqConnect {
	client: rumqttc::AsyncClient,
	event_loop: rumqttc::EventLoop,
	netname: String,
	prikey: x25519_dalek::StaticSecret,
	admin_prikey: Option<x25519_dalek::StaticSecret>,
	subcribe_path: String,
}
use rumqttc::{ConnectReturnCode, Event, Incoming};
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
				options.set_credentials(user, config.network.mq_password.as_ref().unwrap());
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
	pub(crate) async fn sendmsg(&mut self, mut msg: MqMsg) -> Result<(), io::Error> {
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
			error!(
					"network {} cannot push data {:?}: {}",
					self.netname,
					msg.t,
					ret.unwrap_err()
				);

		}
		debug!("network {} send msg time: {:?}", self.netname, start.elapsed());
		Ok(())
	}
}
