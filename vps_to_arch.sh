#!/usr/bin/env bash

#当出现命令行返回值为非0的情况时,脚本直接退出,后续命令不在执行.
set -e

# 验证下载工具.
if command -v wget >/dev/null 2>&1; then
	_download() { wget --no-check-certificate -O- "$@" ; }
elif command -v curl >/dev/null 2>&1; then
	_download() { curl -fL "$@" ; }
else
	echo "没有找到curl或wget,无法执行安装程序,请安装curl或wget." >&2
	exit 2
fi

# 获取Arch Linux镜像源列表.
get_worldwide_mirrors() {
	_download 'https://www.archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4' | awk '/^## /{if ($2 == "Worldwide") { flag=1 } else { flag=0 } } /^#Server/ { if (flag) { sub(/\/\$repo.*/, ""); print $3 } }'
}

cpu_type="$(uname -m)"

# 检测是否为Openvz.
is_openvz() { [ -d /proc/vz -a ! -d /proc/bc ]; }

is_lxc() { grep -aqw container=lxc /proc/1/environ ; }

# 下载bootstrap方法.
download() {
	local path="$1" x=
	shift
	for x in $mirrors; do
		_download "$x/$path" && return 0
	done
	return 1
}

download_and_extract_bootstrap() {
	local sha256 filename
	download iso/latest/sha256sums.txt | fgrep "$cpu_type.tar.gz" > "sha256sums.txt"
	read -r sha256 filename < "sha256sums.txt"
	download "iso/latest/$filename" > "$filename"
	grep -v archlinux-bootstrap-x86_64.tar.gz sha256sums.txt | sha256sum -c || exit 1
	tar -xpzf "$filename"
	rm -f "$filename"
	cp -L /etc/resolv.conf "/root.$cpu_type/etc"

    # 从 arch-chroot 脚本获取的挂载选项.
	mount -t proc proc -o nosuid,noexec,nodev "/root.$cpu_type/proc"
	mount -t sysfs sys -o nosuid,noexec,nodev,ro "/root.$cpu_type/sys"
	mount -t devtmpfs -o mode=0755,nosuid udev "/root.$cpu_type/dev"
	mkdir -p "/root.$cpu_type/dev/pts" "/root.$cpu_type/dev/shm"
	mount -t devpts -o mode=0620,gid=5,nosuid,noexec devpts "/root.$cpu_type/dev/pts"
	mount -t tmpfs -o mode=1777,nosuid,nodev shm "/root.$cpu_type/dev/shm"
	mount -t tmpfs -o nosuid,nodev,mode=0755 run "/root.$cpu_type/run"
	mount -t tmpfs -o mode=1777,strictatime,nodev,nosuid tmp "/root.$cpu_type/tmp"
    # FIXME支持多个分区.
	mount --bind / "/root.$cpu_type/mnt"
	findmnt /boot >/dev/null && mount --bind /boot "/root.$cpu_type/mnt/boot"
	findmnt /boot/efi >/dev/null && mount --bind /boot/efi "/root.$cpu_type/mnt/boot/efi"
	# Debian方法.
	mkdir -p "/root.$cpu_type/run/shm"
	# OpenVZ 方法.
	rm -f "/root.$cpu_type/etc/mtab"
	cp -L /etc/mtab "/root.$cpu_type/etc/mtab"
}

chroot_exec() {
	chroot "/root.$cpu_type" /bin/bash -c "$*"
}

configure_chroot() {
	local m
	for m in $mirrors; do
		echo 'Server = '"$m"'/$repo/os/$arch'
	done >> "/root.$cpu_type/etc/pacman.d/mirrorlist"
    # 如果需要,安装并初始化 hadged.
	if ! is_openvz && ! pidof haveged >/dev/null; then
        # 禁用签名检查,安装并启动 hadged 并重新启用签名检查.
		sed -i.bak "s/^[[:space:]]*SigLevel[[:space:]]*=.*$/SigLevel = Never/" "/root.$cpu_type/etc/pacman.conf"
		chroot_exec 'pacman --needed --noconfirm -Sy haveged && haveged'
		mv "/root.$cpu_type/etc/pacman.conf.bak" "/root.$cpu_type/etc/pacman.conf"
	fi
	chroot_exec 'pacman-key --init && pacman-key --populate archlinux'
	# 更新 archlinux-keyring 在 bootstrap环境中.
	chroot_exec 'pacman --needed --noconfirm -Sy archlinux-keyring'

    # 生成fstab.
	chroot_exec 'genfstab /mnt >> /etc/fstab'
}

save_root_pass() {
	grep '^root:' /etc/shadow > "/root.$cpu_type/root.passwd"
	chmod 0600 "/root.$cpu_type/root.passwd"
}

backup_old_files() {
	cp -fL /etc/hostname /etc/localtime "/root.$cpu_type/etc/" || true
}

delete_all() {
    # 从任何文件/目录中删除不可变标志.
	if command -v chattr >/dev/null 2>&1; then
		find / -type f \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path '/selinux/*' -and ! -path "/root.$cpu_type/*" \) \
			-exec chattr -i {} + 2>/dev/null || true
	fi
	# Delete *all* files from /
	find / \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path '/selinux/*' -and ! -path "/root.$cpu_type/*" \) -delete 2>/dev/null || true
}

# 软件包;
install_packages() {
	local packages="base openssh reflector linux-zen linux-zen-headers linux-firmware  linux-firmware-whence vim bash-completion"
	is_openvz || packages="$packages lvm2"
	[ "$bootloader" != "none" ] && packages="$packages $bootloader"
    # XXX 为 syslinux 安装 gptdisk。删除后 FS#45029 将被关闭.
	[ "$bootloader" = "syslinux" ] && packages="$packages gptfdisk"
	[ -f /sys/firmware/efi/fw_platform_size ] && packages="$packages efibootmgr"
	[ "$network" = "netctl" ] && packages="$packages netctl"
	while read -r _ mountpoint filesystem _; do
		[ "$mountpoint" = "/" -a "$filesystem" = "xfs" ] && packages="$packages xfsprogs"
	done < /proc/mounts
	# Black magic!
	"/root.$cpu_type/usr/lib"/ld-*.so.2 --library-path "/root.$cpu_type/usr/lib" \
		"/root.$cpu_type/usr/bin/chroot" "/root.$cpu_type" /usr/bin/pacstrap -M /mnt $packages
	cp -L "/root.$cpu_type/etc/resolv.conf" /etc
}

restore_root_pass() {
    # 默认密码whoami
	if ! egrep -q '^root:[^$]' "/root.$cpu_type/root.passwd"; then
		echo "root:whoami" | chpasswd
	fi
    cat << "EOF" >/root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDReconVNvAhM7MtKHL0G6iOikJbFJ5Yj5RJsFjQkH5q7mXgmXvoTna+PaVrijxo2yBtOqEvQddWExW/ETnaZP3wvYrKX8Al7lJLG/ntYu/QPHE56uG0itwLEJ0lib2dBYeATx5GAzg7Xh34VjHPvWw/4lb6V4n/n2T4w4807IlLwMGfF3+JWgjIX0dz/OD+LucFljj7Ig0MaLE5xbJMNtK3wTgQ1wHmpsUWftP6sHWeqBqzQHlJc4bihvoxVXEZumukGZ7h0lWyx9iKcSMvQXF/MYGnP8mubKSCHXhk6d8hSyC+UHROAM8IQFNR2WcK9on+nCFVMBLXThpMEaneo4nDcotZuWPTx+NgRpxAROJpJsCF5dP+JWFESrPdxgMIOk4l5+MVHHoJXAIstEhOn+8hVnWxxig4Lwa3E+v+9OPvWicLB6TG1NyBUqQV++sr6Lp9bhR8dBJ/QnM9HnooHVMGn9lZFjCcjaar6Xs9xoalb1/Gbb8UHnRJJHN10Lk47M=
î200~ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDTtnb1Pue7zfKSoIcioBCsN6SrQoaSiZCIT7iKj+J0fx1xACmBAYJa9J7dJFEqUP3LmLzCoAVi8Vpdz+63yZITBHso800XN+5XAtSA8+XY65myCtv4ZmefYxXFO0SkVSV5Oe3ic2ltPvn44WxwHDSSYcjzwpcT7PlQxBqXr0LL5jXET/IXdgclb0aohuXOafI2gUWje4teSSDspNkVBc+9aBlEZ/tIepjSfs6x6IddRR33itT1gmqaGnVkr7x+oecS+/dRK3pOTWp/thUmEAXjGQXiPuc5RDa2GuohXb5DuY8mNID3m8PIjq71b8BmrjXuYm88VA+HtL+K/wUbXOOaXlKk2qLGMCkAWfezkD/L1caQRSmr88f8OPqJYaTxK+7KgYUn2vSysLVXO3HEQAqt/6tQj0dm34yhSr9yFcLZxhpzugwN6H4ynMX+d5Sn5LBi3pMo4VqJ6vH4liVqXHz7066Kz457XPeVyNLKGNm+QWiEHAd/7yHmD9/C+HCP7dPJx1Q5TvU2Ry4CEfiDFc4j1IOl4cBVMZypr+7WFaRjpr/SKvaPpEYpHHyfTopQ7/JIa4C2qaAjXZPuFt+uLR9Bw8YPn5N0vaKzjxqY0ickg45mntcmiSLSubEiBFkmGBcko8bfi3fFnNyD1o//yPq4QfETXODtYnlXiZTw3We2Ww== huan@xia
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDN4ATlveJZ0MQIb50TqAI47ND7YvDk1INLYQeEnNixJroctNuEKT9zY2fsZ+jwpIK12FNLHMQT/LEpfM+UW2AFObgatps8yWKvaKGSUcauBnbQhAiHPepaMPkIUyul4aV5sJ1IOr6CDdWGKeMwhgCPZGOClAgofK7I2X1TunPPN3VdmseBuMyyLnp7ZacQ9iIBmmGUbTKQ5P+tbUnMg43uYe721wHWAdzSBxp4YMW941QfIrg2VSnjeYhaHE0m2nSqkKf11bUtxcktsg7sqad0AECqytw7YRtEQoNf/+OC3GuYpOM2VEXSYmqHf3EXi1dXtMlLU+h9uBetGFBuaOqv root@iZj6cbf6ho0fpj88lfv3lcZ
EOF
}

cleanup() {
	mv "/root.$cpu_type/etc/fstab" "/etc/fstab"
	awk "/\/root.$cpu_type/ {print \$2}" /proc/mounts | sort -r | xargs umount -nl || true
	rm -rf "/root.$cpu_type/"
}

# 配置grub.cfg
configure_bootloader() {
	local root_dev=$(findmnt -no SOURCE /) root_devs= tmp= needs_lvm2=0 uefi=0
	case $root_dev in
	/dev/mapper/*) needs_lvm2=1 ;;
	esac
	if [ -f /sys/firmware/efi/fw_platform_size ]; then
		uefi=$(cat /sys/firmware/efi/fw_platform_size)
	fi

	if [ $needs_lvm2 -eq 1 ]; then
        #某些发行版默认不使用 lvmetad
		sed -i.bak 's/use_lvmetad = 1/use_lvmetad = 0/g' /etc/lvm/lvm.conf
	fi

	if [ "$bootloader" = "grub" ]; then
        # 如果您仍然使用 eth* 作为接口名称,请禁用 ifnames 内核参数;
		grep -q '^[[:space:]]*eth' /proc/net/dev && \
			sed -i.bak 's/GRUB_CMDLINE_LINUX_DEFAULT="/&net.ifnames=0 /' /etc/default/grub

        # 禁用 grahic 显示.
		sed -i.bak 's/^#GRUB_TERMINAL_OUTPUT=console/GRUB_TERMINAL_OUTPUT=console/' /etc/default/grub

		if [ $needs_lvm2 -eq 1 ]; then
			local vg
			vg=$(lvs --noheadings $root_dev | awk '{print $2}')
			root_dev=$(pvs --noheadings | awk -v vg="$vg" '($2 == vg) { print $1 }')
		fi
		for root_dev in $root_dev; do
			tmp=$(lsblk -npsro TYPE,NAME "$root_dev" | awk '($1 == "disk") { print $2}')
			case " $root_devs " in
			*" $tmp "*) 	;;
			*)		root_devs="${root_devs:+$root_devs }$tmp"	;;
			esac
		done
		case $uefi in
		0)
			for root_dev in $root_devs; do
				grub-install --target=i386-pc --recheck --force "$root_dev"
			done
			;;
		64)
			grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
			;;
		esac
		grub-mkconfig > /boot/grub/grub.cfg
	elif [ "$bootloader" = "syslinux" ]; then
        # 如果仍然使用 eth* 作为接口名称,请禁用'奇怪'的 ifnames
		grep -q '^[[:space:]]*eth' /proc/net/dev && tmp="net.ifnames=0"
		syslinux-install_update -ami
		sed -i "s;\(^[[:space:]]*APPEND.*\)root=[^[:space:]]*;\1root=$root_dev${tmp:+ $tmp};" /boot/syslinux/syslinux.cfg
	fi

	if [ $needs_lvm2 -eq 1 ]; then
		mv /etc/lvm/lvm.conf.bak /etc/lvm/lvm.conf
		sed -i '/HOOKS/s/block/& lvm2/' /etc/mkinitcpio.conf
		mkinitcpio -p linux
	fi
}

configure_network() {
	local gateway dev ip

	read -r dev gateway <<-EOF
		$(awk '$2 == "00000000" { ip = strtonum(sprintf("0x%s", $3));
			printf ("%s\t%d.%d.%d.%d", $1,
			rshift(and(ip,0x000000ff),00), rshift(and(ip,0x0000ff00),08),
			rshift(and(ip,0x00ff0000),16), rshift(and(ip,0xff000000),24)) ; exit }' < /proc/net/route)
	EOF

	set -- $(ip addr show dev "$dev" | awk '($1 == "inet") { print $2 }')
	ip=$@

    # # FIXME 尚不支持'P2P'接口,例如 venet.
	if [ "$network" = "systemd-networkd" ]; then
		cat > /etc/systemd/network/default.network <<-EOF
			[Match]
			Name=$dev

			[Network]
			Gateway=$gateway
		EOF
		for ip in $ip; do
			echo "Address=$ip"
		done >> /etc/systemd/network/default.network
		systemctl enable systemd-networkd
	elif [ "$network" = "netctl" ]; then
		cat > /etc/netctl/default <<-EOF
			Interface=$dev
			Connection=ethernet
			IP=static
			Address=($ip)
		EOF
		if [ "$gateway" = "0.0.0.0" ]; then
			echo 'Routes=(0.0.0.0/0)'
		else
			echo "Gateway=$gateway"
		fi >> /etc/netctl/default
		netctl enable default
	fi

	systemctl enable sshd
}

finalize() {
	# OpenVZ hacks
	if is_openvz; then
        # Virtuozzo 7 可与 systemd 配合使用,但需要 /etc/resolvconf/resolv.conf.d 目录.
		mkdir -p /etc/resolvconf/resolv.conf.d
	fi

    # 允许root用户登陆.
	sed -i '/^#PermitRootLogin\s/s/.*/&\nPermitRootLogin yes/' /etc/ssh/sshd_config
    
    # 禁止使用密码登陆.
    sed -i '1i PasswordAuthentication no' /etc/ssh/sshd_config
	
    # 运行 Reflector 来获取更新的镜像.
	
	cat <<-EOF
	
        Reflector:对最近同步的 35 个 HTTPS 服务器进行评级,并按下载速度对它们进行排序.
		
	EOF
	
	reflector -l 35 -p https --sort rate --save /etc/pacman.d/mirrorlist

	cat <<-EOF
		BinGo!
        VPS 成功转换为Arch Linux

        此脚本将$bootloader配置为bootloader，并将$network配置为默认联网工具.

        执行下列命令重启.
		# sync ; reboot -f

        # 服务器默认密码为: whoami
        # 请不要忘记禁止使用密码验证登陆服务器.
	EOF
}

bootloader=grub
network=systemd-networkd
mirrors=

while getopts ":b:m:n:h" opt; do
	case $opt in
	b)
		if ! [ "$OPTARG" = "grub" -o "$OPTARG" = "syslinux" -o "$OPTARG" = "none" ]; then
			echo "指定的引导加载程序无效." >&2
			exit 1
		fi
		bootloader="$OPTARG"
		;;
	m)
		mirrors="${mirrors:+$mirrors }$OPTARG"
		;;
	n)
		if ! [ "$OPTARG" = "systemd-networkd" -o "$OPTARG" = "netctl" -o "$OPTARG" = "none" ]; then
			echo "指定的网络配置系统无效" >&2
			exit 1
		fi
		network="$OPTARG"
		;;
	h)
		cat <<-EOF
            usage: ${0##*/} [options]
              Options:
                -b (grub|syslinux)使用指定的引导加载程序,当省略该选项时,默认为 grub.
                -n (systemd-networkd|netctl)使用指定的网络配置系统,当省略此选项时,它默认为 systemd-networkd.
                -m 镜像 使用提供的镜像（您可以多次指定此选项).

                -h 打印此帮助消息

                警告:
                  在 OpenVZ 容器上，将不会安装引导加载程序，并且网络配置系统将强制执行 netctl。
		EOF
		exit 0
		;;
	:)
		printf "%s: 选项需要一个参数 -- '%s'\n" "${0##*/}" "$OPTARG" >&2
		exit 1
		;;
	?)
		printf "%s: 无效选项 -- '%s'\n" "${0##*/}" "$OPTARG" >&2
		exit 1
		;;
	esac
done
shift $((OPTIND - 1))

[ -z "$mirrors" ] && mirrors=$(get_worldwide_mirrors)


if is_openvz; then
	bootloader=none
	network=netctl
elif is_lxc; then
	bootloader=none
fi

cd /
download_and_extract_bootstrap
configure_chroot
save_root_pass
backup_old_files
delete_all
install_packages
restore_root_pass
cleanup
configure_bootloader
configure_network
finalize
