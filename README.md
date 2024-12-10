# `wgmqc`

目标是实现serverless 的wireguard VPN 管理器

特点:

- 基于内核wireguard 实现(windows/macos 使用rust 实现)
- 无需搭建服务器(使用公开mqtt broker)
- 任意节点可管理网络
- 多网络支持

路线图:
- [x] wireguard 基本功能
- [ ] windows/macos 支持
- [ ] 对mqtt 消息加密
- [ ] 管理界面
- [ ] 具有public ip /full cone 节点支持代理流量
