# WEEK 13

**靶机名称**:vulnhub------**DOUBLETROUBLE: 1**

**靶机链接**:https://www.vulnhub.com/entry/doubletrouble-1,743/

**难度**:*Easy*

**攻击机**:Kali Linux

**使用工具**:[dirtycow](https://github.com/FireFart/dirtycow)

# 简介

日常水一水小靶机~

## 主机发现

`sudo arp-scan -l`

![截屏2021-09-25 上午8.43.31](https://tva1.sinaimg.cn/large/008i3skNly1guskyingyrj616a0f2jwg02.jpg)

发现主机:**10.0.0.13**

`sudo nmap -p- 10.0.0.13`

![截屏2021-09-25 上午8.45.35](https://tva1.sinaimg.cn/large/008i3skNly1gusl0n5hq4j60ui0bmq4u02.jpg)

80与22的经典搭配

![截屏2021-09-25 上午8.46.36](https://tva1.sinaimg.cn/large/008i3skNly1gusl1q4pwaj616g0ii79k02.jpg)

来吧,进行web页面的工作~

## web页面

![截屏2021-09-25 上午8.48.16](https://tva1.sinaimg.cn/large/008i3skNly1gusl3gpgbjj61c00u0q8a02.jpg)

当我看到这个页面,我有四种思路

1.密码爆破,但是看到用户名为邮箱时,我放弃了

2.sql注入,登陆界面绕过等等

3.cms:qsPM9.1,可以找找现成的漏洞

4.密码找回~

![截屏2021-09-25 上午8.51.31](https://tva1.sinaimg.cn/large/008i3skNly1gusl6vif6ej625i0den1w02.jpg)

果然,前辈们的exp才是真爱

不过看了一下脚本,好像都需要先登录...

没办法,先扫描一下路径吧~

`dirsearch -u "http://10.0.0.12"`

![截屏2021-09-25 上午8.57.00](https://tva1.sinaimg.cn/large/008i3skNly1guslck662bj60u00vq7c302.jpg)

这么多有趣的东西~

我们先看看robots.txt,没有什么信息

查看secret目录,发现一张图片,使用`strings`和`exiftool`进行隐写查看,一无所获

查看install目录,诶~有戏~~

![截屏2021-09-25 上午10.31.21](https://tva1.sinaimg.cn/large/008i3skNly1guso2pu5itj61c00u0dl302.jpg)



![截屏2021-09-25 上午11.42.52](/Users/qiao/Library/Application Support/typora-user-images/截屏2021-09-25 上午11.42.52.png)

我们在本地开启mysql服务,创建一个叫做qdpm的数据库,设置允许外部链接

![截屏2021-09-25 下午12.04.30](https://tva1.sinaimg.cn/large/008i3skNly1gusqroqafgj61c00u0tf002.jpg)

直接设置密码为123,然后我们保存,再进行登录~

![截屏2021-09-25 下午12.05.13](https://tva1.sinaimg.cn/large/008i3skNly1gusqsgcrgoj61c00u0tdx02.jpg)

成功登陆啦~

这里我们使用了重新安装的方法覆盖了原来的密码

查看一下功能吧~

不过等等,还记得我们之前找到的Authenticated-RCE吗?直接用啊!

不过exp好像有点问题?

我们先通过admin账号创建一个新用户,登陆后发现了许多新的功能(疑惑?)

然后通过上传头像的功能上传shell.jpg,在burp中进行更改为shell.php.虽然页面返回报错,但是文件成功上传

然后简简单单的nc反弹~

![截屏2021-09-25 下午1.07.15](https://tva1.sinaimg.cn/large/008i3skNly1gussky1xxhj614g0e2tch02.jpg)

## 提权

使用python获得python pty交互shell

使用sudo -l查看特权~

![截屏2021-09-25 下午1.08.36](https://tva1.sinaimg.cn/large/008i3skNly1gussmbdtsxj612c07cabq02.jpg)

使用awk提权~

`sudo awk 'BEGIN {system("/bin/bash")}'`

获得shell~

正当我开心着呢,打开root主目录一看,傻眼了...

![截屏2021-09-25 下午1.09.41](https://tva1.sinaimg.cn/large/008i3skNly1gussngblguj60wg06o3zt02.jpg)

?????

我的可可爱爱的flag呢?

怎么又来一个ova文件???!!

哭~

# double trouble 2

果真如靶机名所说,double trouble!!

我们先把这个ova文件想办法下载下来吧~

使用python开启监听下载

`python3 -m http.server 8888`

然后打开浏览器,下载第二个ova文件~

进行安装,我们开始打第二层....

![截屏2021-09-25 下午1.25.09](https://tva1.sinaimg.cn/large/008i3skNly1gust3j5yejj60yw0dc0xf02.jpg)

ip:**10.0.0.15**

![截屏2021-09-25 下午1.24.54](https://tva1.sinaimg.cn/large/008i3skNly1gust3ctvpsj60tu0bujtq02.jpg)

22,80端口

![截屏2021-09-25 下午1.26.04](https://tva1.sinaimg.cn/large/008i3skNly1gust4im4wzj617c0hcn3502.jpg)

发现了Apache2.2.22,有点老的版本,可以搜一下漏洞~

不过好像没什么发现...

来看看web界面~

![截屏2021-09-25 下午1.27.04](https://tva1.sinaimg.cn/large/008i3skNly1gust5jpo6vj61c00u0qab02.jpg)

登陆?

emmm试试吧

使用burp抓包并重放,发现返回包好像没有什么区别?

我们把请求头参数加上*并保存下来,让sqlmap进行扫描

![截屏2021-09-25 下午2.04.12](https://tva1.sinaimg.cn/large/008i3skNly1gusu86utxij61c00u042j02.jpg)

·

`sqlmap -r burp.cap --random-agent --batch`

没想到啊,居然发现了sql注入漏洞!

不过有点尴尬,是时间盲注...

我们让sqlmap跑一下数据库名,表名,发现了users表

我们把它获取下来

`sqlmap -r burp.cap --random-agent --batch -D doubletrouble -T users --dump`

![截屏2021-09-25 下午2.06.02](https://tva1.sinaimg.cn/large/008i3skNly1gusua2yrkfj60d8086q3g02.jpg)

先尝试一下ssh吧~

第一个账号失败了,但是第二个成功了!

![截屏2021-09-25 下午2.09.04](https://tva1.sinaimg.cn/large/008i3skNly1gusud9k3gyj60x80bedid02.jpg)

ps:如果出现如下情况,只需输入`ssh-keygen -R <靶机ip>`即可![截屏2021-09-25 下午2.09.45](https://tva1.sinaimg.cn/large/008i3skNly1gusudxz99zj61260fs44e02.jpg)

user.txt:`6CEA7A737C7C651F6DA7669109B5FB52`

![截屏2021-09-25 下午2.11.05](https://tva1.sinaimg.cn/large/008i3skNly1gusufc53ynj60wy030mxs02.jpg)

没有sudo命令,尝试一下内核提权吧

很可惜,没有找到类似的漏洞...

在系统探索的过程中,我发现了一个好玩的foothold方式

![截屏2021-09-25 下午2.15.23](https://tva1.sinaimg.cn/large/008i3skNly1gusujt4kj9j60s00aagms02.jpg)

这里是存在一个命令注入点的,很可惜,我们没有扫描到这个pingit.php文件...

同时这里还需要进行fuzz,害,算了~

看到内核的版本如此之低,我们不妨使用dirtycow进行提权!

通过dirtycow修改/etc/passwd文件,将root的密码修改,再使用ssh登陆!

![截屏2021-09-25 下午3.52.23](https://tva1.sinaimg.cn/large/008i3skNly1gusxcqvpswj60xk0eiq7102.jpg)

成功获得root权限!

root.txt:`1B8EEA89EA92CECB931E3CC25AA8DE21`

**PWN!**

## 总结

这次的靶机可以说是十分有新意了!居然层层套娃!

一开始的主机发现平平无奇,但是对web界面探索时,目录爆破起了很大的作用!

我们成功通过install覆盖的方式登陆!

然后通过文件上传webshell反弹shell.

通过sudo -l发现awk,通过awk提权为root

但是root目录下没有flag,而是一个另一个ova文件!

再一次,我们又开始了打靶之路.

对于第二层靶机,我们通过sql注入获得了账号与密码,成功登陆ssh.

我们发现内核版本很低,所以我们通过dirtycow进行提权!最终获得root权限!

## 附录

dirtycow:	https://github.com/FireFart/dirtycow