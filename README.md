# vpstoarch

将任意Linux发行版转换为Arch Linux

## !注意！

> 脚本中自带的公钥为测试用的公钥,并非后门


## 快捷运行方法.

```shell
bash <(curl -sL https://raw.githubusercontent.com/wo2ni/vpstoarch/main/vps_to_arch.sh)
```

## 附加参数

```txt
Options:
   -b (grub|syslinux)使用指定的引导加载程序,当省略该选项时,默认为 grub.
   -n (systemd-networkd|netctl)使用指定的网络配置系统,当省略此选项时,它默认为 systemd-networkd.
   -m 镜像 使用提供的镜像（您可以多次指定此选项).
   -h 打印此帮助消息
```
