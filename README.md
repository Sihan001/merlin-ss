## Shadowsocks for Merlin 华硕路由梅林固件


非原创，提取 https://github.com/hq450/fancyss_history_package 科学上网插件。

#### 机型支持

 **华硕armv7系列** merlin固件

- 华硕 RT-AC68U
- 华硕 RT-AC66U-B1
- 华硕 RT-AC1900
- 华硕 RT-AC1900P
- 华硕 RT-AC87U
- 华硕 RT-AC88U
- 华硕 RT-AC3100
- 华硕 RT-AC3200
- 华硕 RT-AC5300

------

#### 说明

**代理方式**

> 目前支持 gfwlist 白单名、chnroute 中国白单名、全局三种代理模式。

- gfwlist 白单名，只要域名在名单内及配置了黑名单都走代理模式。
- chnroute 白单名，只要ip不在chnroute 内及黑名单都走代理模式。
- 全局，除白单名外，其余都走代理模式。 

**DNS 污染**

> 目前支持3种解决方案：

1. chinaDNS，国内域名走国内DNS；国外域名走国外DNS；但不稳定，chinaDNS老挂。
2. dns2socks，通过 ss 服务器 tcp 转发。
3. ss-tunnle，通过 ss 服务器 upd 转发，需要服务器支持。

**config 配置说明**

1. blacklist.txt，黑名单；无论那种模式，黑名单的IP都通过代理。
2. chnroute.txt，中国白名单。
3. dnsproxyip.txt，纯净 dns 服务器；不设置默认 8.8.8.8 。
4. gfwlist.conf，白名单；可在线更新。
5. serverlist.txt，ss 服务器列表，支持域名；自动选择最快的服务器连接。
6. ss.json，ss 服务器配置，服务器列表配置均需要一样。
7. ssdns.json，ss-tunnle 为 DNS 时 ss 服务器配置。
8. whitelist.txt，白名单，任何时候都不通过代理。

**使用**

sh ss.sh [optiong]

| 命令        | 描述                       |
| ----------- | -------------------------- |
| start       | 以配置文件设置启动服务     |
| restart     | 以配置文件设置重新启动服务 |
| stop        | 关闭服务                   |
| flush_nat   | 清空转发规则表             |
| update_rule | 在线更新gfwlist            |

| 参数                     | 描述                             |
| ------------------------ | -------------------------------- |
| -h                       | 显示帮助                         |
| -d <dns_mode>            | 设置dns污染方案                  |
| -m <proxy_mode>          | 设置代理模式                     |
| -s <ss_server_ip>        | 强制指定ss服务器地址，不自动选择 |
| -n \<dns_server_ip:port> | 强制指定纯净 dns 服务器          |

ex:

```shell
sh ./ss.sh start
sh ./ss.sh restart
sh ./ss.sh stop
sh ./ss.sh flush_nat
sh ./ss.sh update_rule
sh ./ss.sh -h
ss ./ss.sh -d 1 -m 2 -s xx.xx.xx.xx -n 114.114.114.114:53
```