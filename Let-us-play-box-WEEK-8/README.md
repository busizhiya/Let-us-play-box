# Y0usef

**靶机名称**:vulnhub------**Y0USEF**

**靶机链接**:https://www.vulnhub.com/entry/y0usef-1,624/

**难度**:*Easy*

**攻击机**:Kali Linux

**使用工具**:

## 简介

此次,我们打的是一台Easy难度的靶机.有的小伙伴可能会疑惑:"我们怎么不打中高难度的靶机呢?这样不是能学到更多东西吗?"

各位不要失望,其实低难度的靶机不意味着没有高质量的漏洞,恰恰相反,正是因为这些漏洞危害大,利用简单,在生活中又常见,所以才被列为低难度漏洞~

希望大家打实基础,对漏洞进行更加深入的的了解与探究,加油~

本次的特色攻击手段为:403bypass,文件上传

## 信息收集

### 主机发现

老朋友~`sudo arp-scan -l`

![截屏2021-09-22 下午2.30.42](https://tva1.sinaimg.cn/large/008i3skNly1gupe4yphzwj614c0ektdr02.jpg)

### 端口扫描

全端口扫描:`sudo nmap -p- 10.0.0.12`

![截屏2021-09-22 下午2.43.41](https://tva1.sinaimg.cn/large/008i3skNly1gupeiechxvj60s009k0uf02.jpg)

服务版本扫描:` sudo nmap -p22,80 -sC -sV 10.0.0.12`

![截屏2021-09-22 下午2.44.31](https://tva1.sinaimg.cn/large/008i3skNly1gupej8cb8cj612a0g00yd02.jpg)

最基本的22ssh与80Apache服务

OS:Ubuntu

思路似乎很局限,只有web界面这一个突破口!

## web页面

![截屏2021-09-22 下午2.46.21](https://tva1.sinaimg.cn/large/008i3skNly1gupel456ufj61140u041302.jpg)

emm..只有空空的几个大字,"网站建设中",看看页面源代码?

![截屏2021-09-22 下午2.46.55](https://tva1.sinaimg.cn/large/008i3skNly1gupeloirxsj61140u0jvx02.jpg)

这...也什么都没有.

通常来说,我们对web界面的攻击有两种方式:

1.页面很丰富,信息很充足,根据页面功能进行攻击

2.能获取的信息很少,通过路径爆破、网站指纹等获得更多信息~

看来我们要进一步的挖掘web页面啦~

### 指纹识别?

我们介绍一个工具——`whatweb`,用于网站指纹信息挖掘~

指纹识别是什么呢?简单来说,就是通过如相应头,页面关键字等信息获取服务器所使用的环境、操作系统、cms等等...

`whatweb http://10.0.0.12/`

![截屏2021-09-22 下午2.51.20](https://tva1.sinaimg.cn/large/008i3skNly1gupeqaqv0pj61k604eabt02.jpg)

我们获得了很多信息:

​	中间件:Apache2.4.10,

​	OS:Ubuntu Linux

​	PHP:5.5.9

这时,我们就可以搜一下有没有现有的漏洞啦~

`searchsploit Apache 2.4.10`

`searchsploit php 5.5.9`

查看后,均没有符合的漏洞...

害,别气馁,我们还有另一手~

### brute-force👊!

别忘了,文的不行咱们来武的~使用dirsearch扫描目录

`dirsearch  -u "http://10.0.0.12"`

![截屏2021-09-22 下午3.03.57](https://tva1.sinaimg.cn/large/008i3skNly1gupf3fhswkj60zi0nwtdk02.jpg)

查看`/index.php`和`/index.php/login/`页面均无收获,还是和之前一样的空白~

再看看`/adminstration/`目录,可能有戏!

### 403?bypass!!

![截屏2021-09-24 下午5.35.45](https://tva1.sinaimg.cn/large/008i3skNly1guruq2oll1j61140u0ack02.jpg)

emm?403??这可咋整!

当我们在实际的渗透中,往往会看到这样的情况,很多同学可能就放弃了~

但是,不要放弃!这里为大家介绍一些403bypass的方法

请看:附录——**403Bypass**



最终,我们通过burp拦截并修改`X-Forwarded-For: 127.0.0.1`(XFF)头部成功绕过了检测!

如果接下来我们想要在浏览器中持续带着XFF头部访问,要么手工修改每一个数据包,要么通过使用浏览器插件或者burp插件自动添加,这里我们使用浏览器插件——`ModHeader`

安装方法不再赘述,打开火狐浏览器插件自行安装即可

![截屏2021-09-24 下午6.26.29](https://tva1.sinaimg.cn/large/008i3skNly1gurw6vxg22j61080u0q7a02.jpg)

![截屏2021-09-24 下午6.32.07](https://tva1.sinaimg.cn/large/008i3skNly1gurwconyi3j61080u0jug02.jpg)

简简单单~成功bypass!

### 文件上传😆~~

我们尝试`admin/admin`登陆~

成功了!

![截屏2021-09-24 下午6.33.45](https://tva1.sinaimg.cn/large/008i3skNly1gurwedfyzjj61880u0wiy02.jpg)

我们可以看到,旁边有几个功能,其中最令人心动的就是`Upload file`文件上传功能啦!

我们选择kali默认的shell进行上传`/usr/share/webshells/php/php-reverse-shell.php`

![截屏2021-09-24 下午6.43.20](https://tva1.sinaimg.cn/large/008i3skNly1gurwobm844j61880u0n4l02.jpg)

一般来说,文件上传点都会有些许的防护措施,请见附录——**文件上传绕过**

我们修改MIME类型(Content-Type)为`image/png`

![截屏2021-09-24 下午6.43.59](https://tva1.sinaimg.cn/large/008i3skNly1gurwoystejj61880u0gt702.jpg)

成功bypass!

可以看到,它返回了文件的地址,我们访问一下

`http://10.0.0.12/adminstration/upload/files/1632480236php-reverse-shell.php`

![截屏2021-09-24 下午6.45.10](https://tva1.sinaimg.cn/large/008i3skNly1gurwq87rocj61e00can0n02.jpg)

## 提权

照常的python pty升级,我们再看看有什么有趣的东西

查看用户,`yousef`和`guest-cpxNn2`,奇怪的用户...

![截屏2021-09-24 下午6.47.32](https://tva1.sinaimg.cn/large/008i3skNly1gurwsp6mqnj60wa0u04b102.jpg)

我们进入/home目录看看~

![截屏2021-09-24 下午6.49.46](https://tva1.sinaimg.cn/large/008i3skNly1gurwuztqkgj60p006idh402.jpg)

wow~有flag诶!

user.txt:`c3NoIDogCnVzZXIgOiB5b3VzZWYgCnBhc3MgOiB5b3VzZWYxMjM=`

咦?不知道大家有没有觉得这个flag很奇怪!有点像...像...**base64**!!

一般来说,base64的密文包含0-9a-zA-Z/+=这些字符,尤其是屁股后面跟着的"小尾巴"是它最明显的特征!

我们进行base64解码

`cat user.txt | base64 -d`

![截屏2021-09-24 下午6.53.41](https://tva1.sinaimg.cn/large/008i3skNly1gurwz2ojjlj60qw04kaaw02.jpg)

哈哈,多明显啊!直接把账号密码都给我们了

我们使用`su yousef`进行登陆

既然已经知道了密码,我们尝试sudo权限!

![截屏2021-09-24 下午6.54.38](https://tva1.sinaimg.cn/large/008i3skNly1gurx02f5d4j611g090gni02.jpg)

哈哈,居然可以执行全部命令!

`sudo su`成功获得root权限

![截屏2021-09-24 下午6.55.51](https://tva1.sinaimg.cn/large/008i3skNly1gurx1cuxuhj61cs0ekwij02.jpg)

root.txt:`You've got the root Congratulations any feedback content me twitter @y0usef_11root`

**PWN**!简单的提权~

## 总结

本次打靶过程中,我们分享了关于403bypass和文件上传绕过的许多干货!

首先常见的主机发现和端口扫描,我们一笔带过~

在web界面上,我们遇到了困难!只发现了`/adminstration`目录,而且还被限制403...

很多同学可能一下子就放弃了403页面,但是别担心,我们这一次分享了绕过403的很多干货,希望大家能够好好学习记录,在真实的渗透过程中用出来!

对于本次靶机,难点在于对403的绕过,一旦绕过就豁然开朗!

简单的文件上传漏洞,虽然有小小的检测,但是我们通过简单修改MIME类型成功绕过,获得了shell.

本次的提权更是简单,关键在于同学们能否敏锐的观察到user.txt文件的信息并获得账号密码,这点是很重要的!

在平时的渗透过程中,我们也往往会遗漏某些信息,但是我们需要通过不断的训练提升我们的敏锐程度,不能放过一丝一毫!

最后通过简单的`sudo su`成功提权!

## 附录

## 403Bypass

##### 1.旁站绕过

通过修改`Host`但是访问同一ip的方式进行绕过

原:`Host: www.example.com`

现:`Host: abc.example.com`

##### 2.来源欺骗

​	`	Referer: 127.0.0.1`

或`Referer: https://example.com/auth/login`

​	`X-Forwarded-For: 127.0.0.1`

​	`X-Orginating-IP: 127.0.0.1`

​	`	X-Remote-IP: 127.0.0.1`

##### 3.URL覆盖

原:`GET /auth/login HTTP/1.1`

现:访问不受限制的根路径`GET / HTTP/1.1`,但实际URL被重写覆盖了

​    `X-Original-URL: /auth/login`

​	`X-Rewrite-URL: /auth/login`

##### 原理

总的来说,就是欺骗服务器请求的来源与目标

X开头的头部为拓展头部,目前也已经被大多数应用所接受,这些头部常用于多层代理之间.

## 文件上传绕过

##### 1.文件扩展名绕过js前端限制

在上传前先将`shell.php`更改为`shell.jpg`,进行上传

然后使用burp拦截,将`shell.jpg`改为`shell.php`

##### 2.文件类型(MIME)

​	`Content-Type: application/x-php`

​	`Content-Type: image/png`

通过修改Content-Type类型为图片的类型绕过服务端的检测

##### 3.文件头

`GIF89a`

在文件内容的开头加上GIT89a伪造成图片文件

以上几种方法只是最常用的方法,其他方法请自行学习~

