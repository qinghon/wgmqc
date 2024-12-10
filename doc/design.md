# Design

mq message 

type: announce
行为: 节点启动后发出，其他节点回复当前最新状态
body:
```yaml
type: announce
# 当前数据的签名
salt: xxx
data:
  wg:
    name: xxx
    public: x * 32
    # udp
    port: 51821
    # if is null, admin need send `sign` msg , other node ignore
    sign_data: xxx
    ip:
      # ipv4 or ipv6
      - xxx.xxx.xxx.xxx/24
      - xxxx::xxxx/64
```


type: update
行为：节点定期发送，更新ip
body:
```yaml
type: update
# 当前数据的签名
salt: xxx
data: 
  wg:
    name: xxx
    public: x * 32
    # udp
    port: 51821
    sign_data: xxx
    ip:
      # ipv4 or ipv6
      - xxx.xxx.xxx.xxx/24
      - xxxx::xxxx/64
  endpoints:
    lan: 
      - x.x.x.x:51820
    ipv6:
      - [xxxx::xxxx]:51820
    stun:
      - x.x.x.x:51820
    port_map:
      - x.x.x.x:51820
    statics:
      - x.x.x.x:51820
    
    support_udp: true
  # option
  traceroute:
    - pubip: 1.1.1.1
      routes:
      - 192.168.1.1
  
```

type: sign
行为： admin 为node 签发的消息
body:
```yaml
type:
# 当前数据的签名
salt: xxx
data:
  wg:
    public: x * 32
  # sign data 
  sign_data: xxxx
```

type: update_network
行为：admin 发送更新网络配置消息，如ip 网段更新，stun 服务器更新等
body:
```yaml
type: update_network
salt: xxx
data:
  discovery:
    xxx
  network:
    xxx

```

## 转发支持

支持将某一个节点作为转发节点使用，而无需单独搭建转发服务器
转发流量利用wireguard 握手包提取公钥，在不同enpoint间建立转发关系
转发服务器也利用upnp/nap-pmp映射端口(如果在nat 网关之后)

## ipv6 支持

TODO
