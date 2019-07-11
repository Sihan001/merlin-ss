## Shadowsocks for Merlin 华硕路由梅林固件

非原创，提取kon如图

只支持全局模式有和有自动模式

- 全局模式

  除白名单外所有流量走向ss

- 自动模式 

  gfwlist域名会走ss，其余走国内

- DNS  污染

  gfwlist域名解析走google 8.8.8.8解析

- 用法

  ./myss 

  start

  stop

  restart

  auto

  global

  uprule