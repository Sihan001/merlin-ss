#!/bin/sh

# ss for merlin auas ac88u

alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'

# proxy mode
# 0 global
# 1 auto, gfwlist 
# 2 chnroute, china ip
PROXY_MODE=2

# dns mode
# 0 dns2sock
# 1 chinaDNS
# 2 ss-tunnle
DNS_MODE=0
# local proxy dns port
DNS_PORT=7913

# shadowsocks config
SHAD_PATH=`pwd`
SHAD_BIN_PATH=$SHAD_PATH/bin
SHAD_ETC_PATH=$SHAD_PATH/etc
SHAD_CFG_PATH=$SHAD_ETC_PATH/config

SHAD_SERVER_IP="0"

SHAD_CFG=$SHAD_CFG_PATH/ss.json
SHAD_DNS_CFG=$SHAD_CFG_PATH/ssdns.json
# proxy mode 2
# china ip list
SHAD_CHNROUTE=$SHAD_CFG_PATH/chnroute.txt
# proxy dns server
DNS_PROXY_IP=$SHAD_CFG_PATH/dnsproxyip.txt
DNS="0"
# set app run lock
LOCK_FILE=/var/lock/ss.lock

# this route get the dns
ISP_DNS1=$(nvram get wan0_dns|sed 's/ /\n/g'|grep -v 0.0.0.0|grep -v 127.0.0.1|sed -n 1p)
ISP_DNS2=$(nvram get wan0_dns|sed 's/ /\n/g'|grep -v 0.0.0.0|grep -v 127.0.0.1|sed -n 2p)
IFIP_DNS1=`echo $ISP_DNS1|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`
IFIP_DNS2=`echo $ISP_DNS2|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`

# this route local ip
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

	chinadns=`pidof chinadns1`
	if [ -n "$chinadns" ];then 
		echo_date 关闭chinadns进程...
		killall chinadns1 >/dev/null 2>&1
	fi
	
	haveged_process=`pidof haveged`
	if [ -n "$haveged_process" ];then 
		echo_date 关闭haveged进程...
		killall haveged >/dev/null 2>&1
	fi

	sslocal=`pidof ss-local`
	if [ -n "$sslocal" ];then 
		echo_date 关闭ss-local进程...
		killall ss-local >/dev/null 2>&1
	fi

	dns2socks=`pidof dns2socks`
	if [ -n "$dns2socks" ];then 
		echo_date 关闭dns2socks进程...
		killall dns2socks >/dev/null 2>&1
	fi
}

get_server(){
	min=0
	start=1
	
	if [ "$SHAD_SERVER_IP" = "0" ]; then
		if [ -f "$SHAD_CFG_PATH/serverlist.txt" ]; then
			#servers=`cat "$SHAD_CFG_PATH/serverlist.txt"`
			#cat $SHAD_CFG_PATH/serverlist.txt | while read server
			while read server
			do
				echo_date "测试[$server]速度..."
				info=`ping -c 2 "$server" | awk 'NR==3{print}' | awk '{print $4,$7}'`
				if [ -z "$info" ]; then
					echo_date 跳过空记录
				else
					time=`echo $info | awk -F '[=]' '{print $2}'`
					time1=`echo $time | awk -F '[.]' '{print $1}'`
					ip=`echo $info | awk -F '[:]' '{print $1}'`
					if [ -n "$time" ]; then
						if [ $start -eq 1 ]; then
							min=$time1
							SHAD_SERVER_IP=$ip
							start=2
						else
							if [ $min -gt $time1 ]; then
								min=$time1
								SHAD_SERVER_IP=$ip
							fi
						fi
						#echo_date 当前服务器: $SHAD_SERVER_IP
						echo_date 响应时间: $time
					fi
				fi
			done < $SHAD_CFG_PATH/serverlist.txt
		fi
	fi

	echo_date 选用SS服务器: $SHAD_SERVER_IP
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


detect(){
	# 检测jffs2脚本是否开启，如果没有开启，将会影响插件的自启和DNS部分（dnsmasq.postconf）
	if [ "`nvram get jffs2_scripts`" != "1" ];then
		echo_date "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
		echo_date "+     发现你未开启Enable JFFS custom scripts and configs选项！     +"
		echo_date "+    【软件中心】和【科学上网】插件都需要此项开启才能正常使用！！         +"
		echo_date "+     请前往【系统管理】- 【系统设置】去开启，并重启路由器后重试！！      +"
		echo_date "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
		close_in_five
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


restore_conf(){
	echo_date 删除ss相关配置文件...
	rm -rf /jffs/configs/dnsmasq.conf.add
	rm -rf /jffs/configs/chnroute.txt
}

restart_dnsmasq(){
	# Restart dnsmasq
	echo_date 重启dnsmasq服务...
	service restart_dnsmasq >/dev/null 2>&1
}

create_dnsmasq_conf(){

	rm -rf /tmp/wblist.conf

	if [ $DNS_MODE -eq 1 ];then
		echo "local=/#/127.0.0.1#7913" >> /jffs/configs/dnsmasq.conf.add
	else
		echo "#for router itself" >> /tmp/wblist.conf
		echo "server=/.google.com.tw/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.google.com.tw/gfwlist" >> /tmp/wblist.conf
		echo "server=/dns.google.com/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/dns.google.com/gfwlist" >> /tmp/wblist.conf
		echo "server=/.github.com/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.github.com/gfwlist" >> /tmp/wblist.conf
		echo "server=/.github.io/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.github.io/gfwlist" >> /tmp/wblist.conf
		echo "server=/.raw.githubusercontent.com/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.raw.githubusercontent.com/gfwlist" >> /tmp/wblist.conf
		echo "server=/.adblockplus.org/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.adblockplus.org/gfwlist" >> /tmp/wblist.conf
		echo "server=/.entware.net/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.entware.net/gfwlist" >> /tmp/wblist.conf
		echo "server=/.apnic.net/127.0.0.1#7913" >> /tmp/wblist.conf
		echo "ipset=/.apnic.net/gfwlist" >> /tmp/wblist.conf

		cat /tmp/wblist.conf >> /jffs/configs/dnsmasq.conf.add
		cat $SHAD_CFG_PATH/gfwlist.conf >> /jffs/configs/dnsmasq.conf.add
	fi

	if [ $PROXY_MODE -eq 2 -o $DNS_MODE -eq 1 ]; then
		if [ -f /jffs/configs/chnroute.txt ]; then
			echo_date chnroute已生成
		else
			cat $SHAD_CHNROUTE >> /jffs/configs/chnroute.txt
		fi
	fi
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
	iptables -t nat -F SHADOWSOCKS_CHN > /dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS_CHN > /dev/null 2>&1

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
	ipset -F black_list >/dev/null 2>&1 && ipset -X black_list >/dev/null 2>&1
	ipset -F chnroute >/dev/null 2>&1 && ipset -X chnroute >/dev/null 2>&1
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
	ipset -! create black_list nethash && ipset flush black_list
	ipset -! create chnroute nethash && ipset flush chnroute
	
	if [ $PROXY_MODE -eq 2 ]; then
		cat $SHAD_CHNROUTE >> /jffs/configs/chnroute.txt
	fi

	if [ -f /jffs/configs/chnroute.txt ]; then
		sed -e "s/^/add chnroute &/g" /jffs/configs/chnroute.txt | awk '{print $0} END{print "COMMIT"}' | ipset -R
	fi
}

start_haveged(){
	bin=$SHAD_BIN_PATH/haveged
	echo_date "启动haveged，为系统提供更多的可用熵！"
	$bin -w 1024 >/dev/null 2>&1
}


start_ss_redir(){
	start_haveged
	
	bin=$SHAD_BIN_PATH/ss-redir
	# tcp udp go ss
	echo_date $bin的 tcp 走$bin.
	echo_date $bin的 udp 走$bin.

	# echo_date 选用SS服务器: $SHAD_SERVER_IP
	if [ "$SHAD_SERVER_IP" = "0" ]; then
		$bin -c $SHAD_CFG -u -f /var/run/shadowsocks.pid >/dev/null 2>&1
	else
		$bin -s $SHAD_SERVER_IP -c $SHAD_CFG -u -f /var/run/shadowsocks.pid >/dev/null 2>&1
	fi
	echo_date $bin 启动完毕！.
}

start_sslocal(){

	bin=$SHAD_BIN_PATH/ss-local
	echo_date 开启ss-local，提供socks5代理端口：23456

	# echo_date 选用服务器: $SHAD_SERVER_IP
	if [ "$SHAD_SERVER_IP" = "0" ]; then
		$bin -l 23456 -c $SHAD_CFG -u -f /var/run/sslocal1.pid >/dev/null 2>&1
	else
		$bin -s $SHAD_SERVER_IP -l 23456 -c $SHAD_CFG -u -f /var/run/sslocal1.pid >/dev/null 2>&1
	fi

	echo_date $bin 启动完毕！.
}

start_dns(){

	[ -n "$IFIP_DNS1" ] && CDN="$ISP_DNS1" || CDN="114.114.114.114"

	if [ "$DNS" = "0" ];then
		if [ -f $DNS_PROXY_IP ]; then
			DNS=`cat $DNS_PROXY_IP | sed -n '{1p}'`
		else
			DNS="8.8.8.8:53"
		fi
	fi

	[ -n "$DNS" ] && DNS="$DNS" || DNS="8.8.8.8:53"

	# chinaDNS
	if [ $DNS_MODE -eq 1 ]; then
		echo_date 开启chinaDNS，用于dns解析...
		bin=$SHAD_BIN_PATH/chinadns1
		if [ -f /jffs/configs/chnroute.txt ]; then
			$bin -p $DNS_PORT -s $CDN,$DNS -d -c /jffs/configs/chnroute.txt &
		else
			$bin -p $DNS_PORT -s $CDN,$DNS &
		fi
	elif [ $DNS_MODE -eq 2 ]; then
		# ss-tunnel
		echo_date 开启ss-tunnel，用于dns解析...
		bin=$SHAD_BIN_PATH/ss-tunnel
		$bin -c $SHAD_DNS_CFG -l $DNS_PORT -L $DNS -u -f /var/run/sstunnel.pid >/dev/null 2>&1
	else
		# dns2sock
		start_sslocal
		bin=$SHAD_BIN_PATH/dns2socks
		echo_date 开启dns2socks，用于dns解析...
		nohup $bin 127.0.0.1:23456 "$DNS" 127.0.0.1:$DNS_PORT > /dev/null 2>&1 &
	fi 
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
	
	if [ -f "$SHAD_CFG_PATH/whitelist.txt" ];then
		#whitelist=`cat "$SHAD_CFG_PATH/whitelist.txt"`
		while read ip
		do
			ipset -! add white_list $ip >/dev/null 2>&1
		done < $SHAD_CFG_PATH/whitelist.txt
	fi

	if [ -f "$SHAD_CFG_PATH/serverlist.txt" ]; then
		#servers=`cat "$SHAD_CFG_PATH/serverlist.txt"`
		while read ip
		do
			ipset -! add white_list $ip >/dev/null 2>&1
		done < $SHAD_CFG_PATH/serverlist.txt
	fi

	# add black ip
	if [ -f "$SHAD_CFG_PATH/blacklist.txt" ];then
		#blacklist=`cat "$SHAD_CFG_PATH/blacklist.txt"`
		while read ip
		do
			ipset -! add black_list $ip >/dev/null 2>&1
		done < $SHAD_CFG_PATH/blacklist.txt
	fi
	
}


get_action_chain() {
	case "$1" in
		0)
			echo "SHADOWSOCKS_GLO"
		;;
		1)
			echo "SHADOWSOCKS_GFW"
		;;
		2)
			echo "SHADOWSOCKS_CHN"
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
	# IP 黑名单强制走ss
	iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports 3333

	#-----------------------FOR GLOABLE---------------------
	# 创建gfwlist模式nat rule
	iptables -t nat -N SHADOWSOCKS_GLO
	# IP黑名单控制-gfwlist（走ss）
	iptables -t nat -A SHADOWSOCKS_GLO -p tcp -m set --match-set white_list dst -j RETURN
	iptables -t nat -A SHADOWSOCKS_GLO -p tcp -j REDIRECT --to-ports 3333
	
	#-----------------------FOR GFWLIST---------------------
	# 创建gfwlist模式nat rule
	iptables -t nat -N SHADOWSOCKS_GFW
	iptables -t nat -A SHADOWSOCKS_GFW -p tcp -m set --match-set white_list dst -j RETURN
	# IP黑名单控制-gfwlist（走ss）
	iptables -t nat -A SHADOWSOCKS_GFW -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports 3333
	iptables -t nat -A SHADOWSOCKS_GFW -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-ports 3333

	# 创建大陆白名单模式nat rule
	iptables -t nat -N SHADOWSOCKS_CHN
	iptables -t nat -A SHADOWSOCKS_CHN -p tcp -m set --match-set white_list dst -j RETURN
	# cidr黑名单控制-chnroute（走ss）
	iptables -t nat -A SHADOWSOCKS_CHN -p tcp -m set ! --match-set chnroute dst -j REDIRECT --to-ports 3333

	# 流量分配
	iptables -t nat -I PREROUTING -p tcp -j $(get_action_chain $PROXY_MODE)
	#iptables -t nat -I PREROUTING -p tcp -j SHADOWSOCKS
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
	
	add_white_black_ip
	apply_nat_rules
}
 

apply_ss(){
	echo_date ======================= 梅林固件 - 【科学上网】 ========================
	echo_date
	echo_date ------------------------- 启动【科学上网】 -----------------------------
	kill_process
	detect
	get_server
	restore_conf
	restart_dnsmasq
	flush_nat
	# start
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

start(){
	set_lock
	echo_date 正在启动shadowsocks...
	set_ulimit
	apply_ss
	echo_date 已启动shadowsocks.
	unset_lock
}

update_rule(){
	echo_date 正在下载gfwlist文件
	url_main="https://raw.githubusercontent.com/Sihan001/merlin-ss/master/etc/config"
	wget --no-check-certificate --timeout=8 -qO - "$url_main"/gfwlist.conf > /tmp/gfwlist.conf
	md5sum_gfwlist1=$(md5sum /tmp/gfwlist.conf | sed 's/ /\n/g'| sed -n 1p)
	md5sum_gfwlist2=$(md5sum $SHAD_CFG_PATH/gfwlist.conf | sed 's/ /\n/g'| sed -n 1p)
	if [ "$md5sum_gfwlist1"x != "$md5sum_gfwlist2"x ];then
		echo_date 下载完成，校验通过，将临时文件覆盖到原始gfwlist文件
		mv /tmp/gfwlist.conf $SHAD_CFG_PATH/gfwlist.conf
		create_dnsmasq_conf
		restart_dnsmasq
		echo_date 【更新成功】你的gfwlist已经更新到最新了哦~
	else
		echo_date 你的gfwlist已经是最新，无须更新！
	fi
}

# dns mode
# 0 dns2sock
# 1 chinaDNS
# 2 ss-tunnle
get_dns_mode(){
	case "$1" in
		0)
			echo "dns2sock模式"
		;;
		1)
			echo "chinaDNS模式"
		;;
		2)
			echo "ss-tunnle模式"
		;;
	esac
}

# proxy mode
# 0 global
# 1 auto, gfwlist 
# 2 chnroute, china ip
get_proxy_mode(){
	case "$1" in
		0)
			echo "全局模式"
		;;
		1)
			echo "自动(fgwlist)模式"
		;;
		2)
			echo "中国白名单模式"
		;;
	esac
}

get_server_mode(){
	if [ "$SHAD_SERVER_IP" = "0" ]; then
		echo "自动选择"
	else
		echo "指定:$SHAD_SERVER_IP"
	fi
}

get_dns_server(){
	if [ "$DNS" = "0" ]; then
		echo "选用配置文件"
	else
		echo "指定:$DNS"
	fi
}

get_help(){
	echo -e './ss.sh [command]'
	echo -e '[command:]'
	echo -e '\tstart\t按配置文件启动科学上网'
	echo -e '\trestart\t按配置文件重新启动科学上网'
	echo -e '\tstop\t结束科学上网'
	echo -e '\tflush_nat\t清空转发规则'
	echo -e '\tupdate_rule\t更新转发规则'

	echo -e '-d\tdns模式'
	echo -e '\t0 dns2sock模式(默认)'
	echo -e '\t1 chinaDNS模式'
	echo -e '\t2 ss-tunnle模式'

	echo -e '-m\t代理模式'
	echo -e '\t0 全局模式'
	echo -e '\t1 gwflist模式'
	echo -e '\t2 大陆白单模式(默认)'

	echo -e '-s\t<ip_addr>\t指定ss服务器地址'
	echo -e '-n\t<ip_addr:port>\t指定外部DNS服务器地址,防止污染'
	echo -e '-h\t显示帮助'
}

case $1 in
    start)
    	echo_date init 
	;;
    restart) 
		echo_date init 
	;;
	stop) 
		stop
		exit
	;;
	flush_nat) 
		set_lock
		flush_nat
		unset_lock
		exit
	;;
	update_rule)
		update_rule
		exit
	;;
	-h)
		get_help
		exit
	;;
    -d) param=$2
        DNS_MODE=$param
        shift ;;
    -m) param=$2
		PROXY_MODE=$param
		shift ;;
	-s) param=$2
		SHAD_SERVER_IP=$param
		shift ;;
	-n) param=$2
		DNS=$param
		shift ;;
	*) echo "$1 is not an option";;
esac

echo_date 初始化配置...
echo_date dns模式:$(get_dns_mode $DNS_MODE)
echo_date proxy模式:$(get_proxy_mode $PROXY_MODE)
echo_date ss服务器:$(get_server_mode)
echo_date dns服务器:$(get_dns_server)

if [ "$1" = "restart" ]; then
	restart
else
	start
fi
