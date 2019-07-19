## Shadowsocks for Merlin 华硕路由梅林固件

------

非原创，提取 https://github.com/hq450/fancyss_history_package 科学上网插件。

#### 机型支持

 目前只测试RT-AC88U merlin固件，理论与ac88u同芯片

------

**使用**

目前支持 gfwlist 白单名、chnroute 中国白单名、全局三种代理模式。

- gfwlist 白单名，只要域名在名单内及配置了黑名单都走代理模式。
- chnroute 白单名，只要ip不在chnroute 内及黑名单都走代理模式。
- 全局，除白单名外，其余都走代理模式。 

**DNS 污染**

目前支持3种解决方案：

1. chinaDNS，国内域名走国内DNS；国外域名走国外DNS；但不稳定，chinaDNS老挂。
2. dns2socks，通过ss 服务器tcp转发。
3. ss-tunnle，通过ss 服务器upd转发，需要服务器支持。

**config 配置**

1. blacklist.txt，黑名单；无论那种模式，黑名单的IP都通过代理。
2. chnroute.txt，中国白名单；
3. dnsproxyip.txt，国外dns服务器；不设置以 8.8.8.8为主。
4. gfwlist.conf，国外白名单；
5. serverlist.txt，ss服务器列表，支持域名；会自动选择最快的服务器连接。
6. ss.json，ss服务器配置。
7. ssdns.json，ss-tunnle 为 DNS 时ss服务器配置。
8. whitelist.txt，白名单，任何时候都不通过代理。

**参数**

./ss.sh [command]

| start       | 以配置文件设置启动服务     |
| ----------- | -------------------------- |
| restart     | 以配置文件设置重新启动服务 |
| stop        | 结束服务                   |
| flush_nat   | 清空转发规则表             |
| update_rule | 在线更新gfwlist            |

| -h                      | 显示帮助                       |
| ----------------------- | ------------------------------ |
| -d <dns_mode>           | 设置dns污染方案                |
| -m <proxy_mode>         | 设置代理模式                   |
| -s <ss_server_ip>       | 指定ss服务器地址，不再自动选择 |
| -n <dns_server_ip:port> | 指定纯净 dns                   |

