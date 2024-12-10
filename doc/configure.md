

## default create config.yaml

```yaml
# network01.yaml
wg:
  name: xxx
  public: x * 32
  private: x * 32
  # udp
  port: 51821
  interval: 120
  ip:
  # ipv4 or ipv6
  - xxx.xxx.xxx.xxx/24
  - xxxx::xxxx/64

discovery:
  # if passive mode, node ignore other node's update message(no need to update), 
  # this full passive mode is not recommended
  passive: false
  # tcp
  port: 51821
  stuns:
  - stun4.l.google.com
  pubip:
  - url: http://myip.ipip.net
    # option, match ip from body
    regex: 

network:
  # network id, use x25519 pubkey base64
  id: xxx
  name: abcd1234
  desc: ""
  send_internal: true
  interface_policy:
    # option
    # priority more than "block" or "allow" 
    interface: eth0
    # "block" has a higher priority than "allow"
    block_interface_regex: xxx
    allow_interface_regex: xxx

  broker: broker.nm.wusheng.bid
  mq_user: admin
  mq_password: xxx
  # if node allow admin
  broker_admin_pubkey: xxx
  broker_admin_prikey: xxx
  # public, private
  allow_policy: public
  update_interval: 120
  deny:
    - peer key

status:
  peers:
  - key: xxx
    name: 
    endpoint: 
    allow_ips:
    # ipv4 or ipv6
    - xxx.xxx.xxx.xxx/24
    - xxxx::xxxx/64

```
