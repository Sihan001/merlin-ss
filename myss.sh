#!/bin/sh

# merlin for auas router  shadowsocks sh script
alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'
# shadowsocks mode 
# 2 global, 1 auto(gfw)
SS_MODE=1
DNS=8.8.8.8:53
# path
SS_PATH=/mnt/sda1/opt/shadowsocks
SS_BIN=$SS_PATH/bin
SS_ETC=$SS_PATH/etc
SS_CONFIG=$SS_ETC/config
CONFIG_FILE=$SS_CONFIG/ss.json

LOCK_FILE=/var/lock/ss.lock
DNS_PORT=7913

ISP_DNS1=$(nvram get wan0_dns|sed 's/ /\n/g'|grep -v 0.0.0.0|grep -v 127.0.0.1|sed -n 1p)
ISP_DNS2=$(nvram get wan0_dns|sed 's/ /\n/g'|grep -v 0.0.0.0|grep -v 127.0.0.1|sed -n 2p)
IFIP_DNS1=`echo $ISP_DNS1|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`
IFIP_DNS2=`echo $ISP_DNS2|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`

lan_ipaddr=$(nvram get lan_ipaddr)
ip_prefix_hex=`nvram get lan_ipaddr | awk -F "." '{printf ("0x%02x", $1)} {printf ("%02x", $2)} {printf ("%02x", $3)} {printf ("00/0xffffff00\n")}'`

# function
set_lock(){
	exec 1000>"$LOCK_FILE"
	flock -x 1000
}

unset_lock(){
	flock -u 1000
	rm -rf "$LOCK_FILE"
}

set_ulimit(){
	ulimit -n 16384
	echo 1 > /proc/sys/vm/overcommit_memory
}

kill_process(){
	ssredir=`pidof ss-redir`
	if [ -n "$ssredir" ];then 
		echo_date 关闭ss-redir进程...
		killall ss-redir >/dev/null 2>&1
	fi
	
	sstunnel=`pidof ss-tunnel`
	if [ -n "$sstunnel" ];then 
		echo_date 关闭ss-tunnel进程...
		killall ss-tunnel >/dev/null 2>&1
	fi
	
	haveged_process=`pidof haveged`
	if [ -n "$haveged_process" ];then 
		echo_date 关闭haveged进程...
		killall haveged >/dev/null 2>&1
	fi
}

restore_conf(){
	echo_date 删除ss相关的名单配置文件.
	rm -rf /jffs/configs/dnsmasq.conf.add
}

restart_dnsmasq(){
	# Restart dnsmasq
	echo_date 重启dnsmasq服务...
	service restart_dnsmasq >/dev/null 2>&1
}

start_haveged(){
	BIN=$SS_BIN/haveged
	echo_date "启动haveged，为系统提供更多的可用熵！"
	$BIN -w 1024 >/dev/null 2>&1
}

flush_nat(){
	echo_date 清除iptables规则和ipset...
	# flush rules and set if any
	nat_indexs=`iptables -nvL PREROUTING -t nat |sed 1,2d | sed -n '/SHADOWSOCKS/='|sort -r`
	for nat_index in $nat_indexs
	do
		iptables -t nat -D PREROUTING $nat_index >/dev/null 2>&1
	done
	#iptables -t nat -D PREROUTING -p tcp -j SHADOWSOCKS >/dev/null 2>&1
	
	iptables -t nat -F SHADOWSOCKS > /dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS > /dev/null 2>&1
	iptables -t nat -F SHADOWSOCKS_GFW > /dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS_GFW > /dev/null 2>&1
	iptables -t nat -F SHADOWSOCKS_GLO > /dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS_GLO > /dev/null 2>&1

	mangle_indexs=`iptables -nvL PREROUTING -t mangle |sed 1,2d | sed -n '/SHADOWSOCKS/='|sort -r`
	for mangle_index in $mangle_indexs
	do
		iptables -t mangle -D PREROUTING $mangle_index >/dev/null 2>&1
	done
	#iptables -t mangle -D PREROUTING -p udp -j SHADOWSOCKS >/dev/null 2>&1
	
	iptables -t mangle -F SHADOWSOCKS >/dev/null 2>&1 && iptables -t mangle -X SHADOWSOCKS >/dev/null 2>&1
	
	#iptables -t nat -D OUTPUT -p tcp -m set --match-set router dst -j REDIRECT --to-ports 3333 >/dev/null 2>&1
	#iptables -t nat -F OUTPUT > /dev/null 2>&1
	
	# flush ipset
	ipset -F white_list >/dev/null 2>&1 && ipset -X white_list >/dev/null 2>&1
	ipset -F gfwlist >/dev/null 2>&1 && ipset -X gfwlist >/dev/null 2>&1
}

detect(){
	# 检测jffs2脚本是否开启，如果没有开启，将会影响插件的自启和DNS部分（dnsmasq.postconf）
	if [ "`nvram get jffs2_scripts`" != "1" ];then
		echo_date "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
		echo_date "+     发现你未开启Enable JFFS custom scripts and configs选项！     +"
		echo_date "+    【软件中心】和【科学上网】插件都需要此项开启才能正常使用！！         +"
		echo_date "+     请前往【系统管理】- 【系统设置】去开启，并重启路由器后重试！！      +"
		echo_date "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	fi
	
	# 检测是否在lan设置中是否自定义过dns,如果有给干掉
	if [ -n "`nvram get dhcp_dns1_x`" ];then
		nvram unset dhcp_dns1_x
		nvram commit
	fi
	if [ -n "`nvram get dhcp_dns2_x`" ];then
		nvram unset dhcp_dns2_x
		nvram commit
	fi
}

load_module(){
	xt=`lsmod | grep xt_set`
	OS=$(uname -r)
	if [ -f /lib/modules/${OS}/kernel/net/netfilter/xt_set.ko ] && [ -z "$xt" ];then
		echo_date "加载xt_set.ko内核模块！"
		insmod /lib/modules/${OS}/kernel/net/netfilter/xt_set.ko
	fi
}

# create ipset rules
create_ipset(){
	echo_date 创建ipset名单
	ipset -! create white_list nethash && ipset flush white_list
	ipset -! create gfwlist nethash && ipset flush gfwlist
}

create_dnsmasq_conf(){
	
	rm -rf /tmp/wblist.conf
	rm -rf /jffs/configs/dnsmasq.conf.add

	echo "#for router itself" >> /tmp/wblist.conf
	echo "server=/.google.com.tw/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.google.com.tw/router" >> /tmp/wblist.conf
	echo "server=/dns.google.com/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/dns.google.com/router" >> /tmp/wblist.conf
	echo "server=/.github.com/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.github.com/router" >> /tmp/wblist.conf
	echo "server=/.github.io/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.github.io/router" >> /tmp/wblist.conf
	echo "server=/.raw.githubusercontent.com/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.raw.githubusercontent.com/router" >> /tmp/wblist.conf
	echo "server=/.adblockplus.org/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.adblockplus.org/router" >> /tmp/wblist.conf
	echo "server=/.entware.net/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.entware.net/router" >> /tmp/wblist.conf
	echo "server=/.apnic.net/127.0.0.1#7913" >> /tmp/wblist.conf
	echo "ipset=/.apnic.net/router" >> /tmp/wblist.conf
	
	cat /tmp/wblist.conf >> /jffs/configs/dnsmasq.conf.add
	cat $SS_CONFIG/gfwlist.conf >> /jffs/configs/dnsmasq.conf.add
}

start_dns(){
	echo_date 开启ss-tunnel，用于dns解析...
	BIN=$SS_BIN/ss-tunnel
	$BIN -c $CONFIG_FILE -l $DNS_PORT -L $DNS -u -f /var/run/sstunnel.pid >/dev/null 2>&1
}

start_ss_redir(){
	start_haveged
	
	BIN=$SS_BIN/ss-redir
	# tcp udp go ss
	echo_date $BIN的 tcp 走$BIN.
	echo_date $BIN的 udp 走$BIN.
	$BIN -c $CONFIG_FILE -u -f /var/run/shadowsocks.pid >/dev/null 2>&1
	echo_date $BIN 启动完毕！.
}

close_in_five(){
	echo_date "插件将在5秒后自动关闭！！"
	sleep 1
	echo_date 5
	sleep 1
	echo_date 4
	sleep 1
	echo_date 3
	sleep 1
	echo_date 2
	sleep 1
	echo_date 1
	sleep 1
	echo_date 0
	echo_date "插件已关闭！！"
	echo_date ======================= 梅林固件 - 【科学上网】 ========================
	unset_lock
	exit
}

get_wan0_cidr(){
	netmask=`nvram get wan0_netmask`
	local x=${netmask##*255.}
	set -- 0^^^128^192^224^240^248^252^254^ $(( (${#netmask} - ${#x})*2 )) ${x%%.*}
	x=${1%%$3*}
	suffix=$(( $2 + (${#x}/4) ))
	prefix=`nvram get wan0_ipaddr`
	if [ -n "$prefix" -a -n "$netmask" ];then
		echo $prefix/$suffix
	else
		echo ""
	fi
}

add_white_black_ip(){
	# white ip/cidr
	[ -n "$IFIP_DNS1" ] && ISP_DNS_a="$ISP_DNS1" || ISP_DNS_a=""
	[ -n "$IFIP_DNS2" ] && ISP_DNS_b="$ISP_DNS2" || ISP_DNS_b=""
	ip_lan="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 223.5.5.5 223.6.6.6 114.114.114.114 114.114.115.115 1.2.4.8 210.2.4.8 117.50.11.11 117.50.22.22 180.76.76.76 119.29.29.29 $ISP_DNS_a $ISP_DNS_b $(get_wan0_cidr)"
	for ip in $ip_lan
	do
		ipset -! add white_list $ip >/dev/null 2>&1
	done
	
	if [ -f "$SS_CONFIG/whitelist.txt" ];then
		for ip in `cat $SS_CONFIG/whitelist.txt`
		do
			ipset -! add white_list $ip >/dev/null 2>&1
		done
	fi
	
}

get_action_chain() {
	case "$1" in
		0)
			echo "RETURN"
		;;
		1)
			echo "SHADOWSOCKS_GFW"
		;;
		2)
			echo "SHADOWSOCKS_GLO"
		;;
	esac
}

apply_nat_rules(){
	#----------------------BASIC RULES---------------------
	echo_date 写入iptables规则到nat表中...
	# 创建SHADOWSOCKS nat rule
	iptables -t nat -N SHADOWSOCKS
	
	# IP/cidr/白域名 白名单控制（不走ss）
	iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set white_list dst -j RETURN

	#-----------------------FOR GLOABLE---------------------
	# 创建gfwlist模式nat rule
	iptables -t nat -N SHADOWSOCKS_GLO
	# IP黑名单控制-gfwlist（走ss）
	iptables -t nat -A SHADOWSOCKS_GLO -p tcp -j REDIRECT --to-ports 3333
	
	#-----------------------FOR GFWLIST---------------------
	# 创建gfwlist模式nat rule
	iptables -t nat -N SHADOWSOCKS_GFW
	# IP黑名单控制-gfwlist（走ss）
	iptables -t nat -A SHADOWSOCKS_GFW -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-ports 3333
	#iptables -t nat -A OUTPUT -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-ports 3333
	
	# 把最后剩余流量重定向到相应模式的nat表中对应的主模式的链
	case $SS_MODE in
	1)
		iptables -t nat -I PREROUTING -p tcp -j $(get_action_chain $SS_MODE)
		;;
	2)
		iptables -t nat -I PREROUTING -p tcp -j SHADOWSOCKS
		iptables -t nat -I PREROUTING -p tcp -j $(get_action_chain $SS_MODE)
		;;
	esac
}

load_nat(){
	nat_ready=$(iptables -t nat -L PREROUTING -v -n --line-numbers|grep -v PREROUTING|grep -v destination)
	i=120
	until [ -n "$nat_ready" ]
	do
		i=$(($i-1))
		if [ "$i" -lt 1 ];then
			echo_date "错误：不能正确加载nat规则!"
			close_in_five
		fi
		sleep 1
		nat_ready=$(iptables -t nat -L PREROUTING -v -n --line-numbers|grep -v PREROUTING|grep -v destination)
	done
	echo_date "加载nat规则!"
	#create_ipset
	add_white_black_ip
	apply_nat_rules
}

apply_ss(){
	echo_date ======================= 梅林固件 - 【科学上网】 ========================
	echo_date
	echo_date ------------------------- 启动【科学上网】 -----------------------------
	kill_process
	restore_conf
	restart_dnsmasq
	flush_nat
	# start
	detect
	load_module
	create_ipset
	create_dnsmasq_conf
	start_ss_redir
	start_dns
	load_nat
	restart_dnsmasq
	echo_date ------------------------ 【科学上网】 启动完毕 ------------------------
}

disable_ss(){
	echo_date ======================= 梅林固件 - 【科学上网】 ========================
	echo_date
	echo_date ------------------------- 关闭【科学上网】 -----------------------------
	kill_process
	restore_conf
	restart_dnsmasq
	flush_nat
	echo_date ------------------------ 【科学上网】已关闭 ----------------------------
}

start(){
	set_lock
	echo_date 正在启动shadowsocks...
	set_ulimit
	apply_ss
	echo_date 已启动shadowsocks.
	unset_lock
}

stop(){
	set_lock
	echo_date 正在停止shadowsock...
	disable_ss
	echo_date
	echo_date 你已经成功关闭shadowsocks服务~
	echo_date See you again!
	echo_date 已停止shadowscok.
	unset_lock
}

restart(){
	set_lock
	echo_date 正在停止shadowsock...
	disable_ss
	echo_date 正在重启shadowsocks...
	set_ulimit
	apply_ss
	echo_date 已启动shadowsocks.
	unset_lock
}

auto(){
	stop
	SS_MODE=1
	echo_date 正在切换到自动模式
	start	
}

global(){
	stop
	SS_MODE=2
	echo_date 正在切换到全局模式
	start
}

uprule(){
	echo_date 正在下载gfwlist文件
	url_main="https://raw.githubusercontent.com/Sihan001/merlin-ss/master/etc/config"
	wget --no-check-certificate --timeout=8 -qO - "$url_main"/gfwlist.conf > /tmp/gfwlist.conf
	md5sum_gfwlist1=$(md5sum /tmp/gfwlist.conf | sed 's/ /\n/g'| sed -n 1p)
	md5sum_gfwlist2=$(md5sum $SS_CONFIG/gfwlist.conf | sed 's/ /\n/g'| sed -n 1p)
	if [ "$md5sum_gfwlist1"x != "$md5sum_gfwlist2"x ];then
		echo_date 下载完成，校验通过，将临时文件覆盖到原始gfwlist文件
		mv /tmp/gfwlist.conf $SS_CONFIG/gfwlist.conf
		create_dnsmasq_conf
		restart_dnsmasq
		echo_date 【更新成功】你的gfwlist已经更新到最新了哦~
	else
		echo_date 你的gfwlist已经是最新，无须更新！
	fi
}

# shell
case $1 in
start)
	start
	;;
stop)
	stop
	;;
restart)
	restart
	;;
flush_nat)
	set_lock
	flush_nat
	unset_lock
	;;
auto)
	auto
	;;
global)
	global
	;;
uprule)
	uprule
	;;
esac