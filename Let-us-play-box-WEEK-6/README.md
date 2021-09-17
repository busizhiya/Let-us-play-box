# 模版

**靶机名称**:vulnhub------**EvilBox: One**

**靶机链接**:https://www.vulnhub.com/entry/evilbox-one,736/

**难度**:*Easy*

**攻击机**:Kali Linux

**使用工具**:fping、ffuf

## 主机发现

还记得ping扫描吗,它只能对单个地址发送ping请求,并不能做到网段的扫描,我们之前结合shell脚本进行网段的扫描

此次介绍一个工具,`fping`

`fping -gaq 10.0.0.0/24`

-g 通过指定网段生成扫描目标列表(扫描网段)

-a 显示存活的主机

-q 安静模式,不显示具体每一个包的情况

![截屏2021-09-14 下午5.34.28](https://tva1.sinaimg.cn/large/008i3skNly1gugahm8kftj60d808e0t502.jpg)

发现ip——`10.0.0.37`

ps:此处无法显示mac地址,请自行查证

### 端口扫描

`sudo nmap -p- -sV -sC --min-rate=2000 -Pn 10.0.0.37 `

![截屏2021-09-14 下午5.25.32](https://tva1.sinaimg.cn/large/008i3skNgy1gugaa419tvj616o0j2n3u02.jpg)



我们发现了22 SSH服务和80 HTTP服务

WEB:Apache 2.4.38,

OS:Debian

## web页面

我们打开浏览器,访问.

![截屏2021-09-14 下午8.52.08](https://tva1.sinaimg.cn/large/008i3skNgy1gugg7asefhj618e0u0qel02.jpg)

发现是默认配置页面.老规矩,进行目录爆破

### 目录爆破

目录爆破,也称为**强制访问**

上次我们介绍过dirsearch,这次介绍一个更为强大的工具——`gubuster`

这款工具默认没有安装,输入`sudo apt install gobuster`即可安装

`gobuster dir -u http://10.0.0.37 -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x txt,html,php`

由于gobuster是一款非常强大的工具,可以进行dns、fuzz等多种扫描.所以我们首先指定扫描类型为`dir`,目录探测

其次,设置`-u`参数指定目标url

`-w`设置字典路径.此处使用的是seclists字典,一款包含了非常的渗透环境的强大字典,使用`sudo apt install seclists`安装

`-x`指定后缀名.此处我们扫描后缀名为txt,html和php的文件(Windows下还可以指定jsp、asp等)

![截屏2021-09-14 下午9.08.59](https://tva1.sinaimg.cn/large/008i3skNgy1guggotj08lj61i20n846202.jpg)

可以发现secret目录,我们再扫一下secret目录下的文件

`gobuster dir -u http://10.0.0.37/secret -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x txt,html,php`

![截屏2021-09-14 下午10.05.10](https://tva1.sinaimg.cn/large/008i3skNgy1gugib9t96cj61xu0r24cc02.jpg)



虽然网络延迟不小,但是我们依旧发现了一个神奇的文件,`evil.php`

evil,邪恶的.看来这是一个恶意的php文件,有可能是后门或者webshell之类的东西~

我们先通过浏览器访问一下

![截屏2021-09-14 下午10.06.44](https://tva1.sinaimg.cn/large/008i3skNgy1gugicvo8huj61ej0u0q4t02.jpg)

...是空的.

按照我们的经验,一个webshell往往会有一个密码,即**参数名**

我们可以通过fuzz的方式暴力猜测参数名!

如果有条件使用Burp Pro的同学可以通过burp的intruder进行爆破

### FUZZ~~

这里我们介绍一个工具,`ffuf`

`ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -w vul.txt:VUL -u http://10.0.0.37/secret/evil.php?PARAM=VUL -fs 0 `

`-w`指定字典名并设置参数名

`-u`指定目标url并使用参数模版

`-fs 0`指定过滤器,过滤掉响应体长度为0的响应包

vul.txt的内容为一些基础字符和特殊字符(如引号,括号等),尝试引起报错或注入

很可惜,并没有获得爆破出结果...

![截屏2021-09-15 下午10.19.57](https://tva1.sinaimg.cn/large/008i3skNly1guhod05au8j31k00p0wlc.jpg)

我们试试执行命令呢

`ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.0.0.37/secret/evil.php?FUZZ=id -fs 0`

此处因为只有一个字典,默认使用`FUZZ`作为参数变量名

![截屏2021-09-15 下午10.21.06](https://tva1.sinaimg.cn/large/008i3skNly1guhoe3hzcfj61kq0o6dml02.jpg)

很可惜,依旧没有结果...

我们再想想,这个后门除了可以执行命令,还能干什么呢...

对!文件包含!

我们尝试指定一个一定存在的文件名...

`ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.0.0.37/secret/evil.php?FUZZ=../index.html -fs 0`

`../index.html`,即默认界面!

![截屏2021-09-15 下午10.22.49](https://tva1.sinaimg.cn/large/008i3skNgy1guhofwvbb4j61k40oogsr02.jpg)

GOT IT!

果然是文件包含,参数为command.

#### 文件包含-读

我们打开浏览器,看看能不能查看/etc/passwd文件

![截屏2021-09-15 下午10.25.08](https://tva1.sinaimg.cn/large/008i3skNgy1guhoiaqkm8j61140u0k0702.jpg)

可以看到有一个用户`mowree`

我们尝试读取一下evil.php的原码吧~

奇怪,怎么不行?

原来,evil.php的内容被读取后输出,默认被当作php的脚本解析了!

我们这里介绍一种php封装器,通过使用filter方法将内容先进行base64加密然后再输出,我们可以凭借这种方式读取php文件~

`command=php://filter/convert.base64-encode/resource=evil.php`

![截屏2021-09-15 下午10.49.04](https://tva1.sinaimg.cn/large/008i3skNly1guhp78pv1hj61i20lon1c02.jpg)

可以看到,就是一个文件包含~

#### 文件包含-写

其实啊,php封装器还提供了filter下的**写**方法

`command=php://filter/write=convert.base64-decode/resource=test.php&txt=MTIz`

如果成功的话,就会在当前目录下的test.php文件写入MTIz的base64decode,也就是123.

我们尝试执行payload并访问test.php

不过很可惜,失败了...

这可能说明我们没有对当前目录的写入权限...

### id_rsa?

到了这里,我们梳理一下之前的内容

我们通过端口扫描知道它开放了22ssh端口,同时我们发现了mowree用户~

这个时候我们想一想,有没有可能通过获取该用户的ssh密钥进行登录呢~

我们首先使用`ssh mowree@10.0.0.37 -v`详细的查看ssh的情况

![截屏2021-09-16 上午7.33.02](https://tva1.sinaimg.cn/large/008i3skNgy1gui4cfatc6j60tu09277b02.jpg)

可以看出,ssh可以使用publickey进行登录!

那我们该怎么获取私钥呢?

在.ssh目录下有两个关键文件

1.authorized_keys

这里面存储着成功登录者的公钥

我们尝试读取一下

![截屏2021-09-16 上午8.41.47](https://tva1.sinaimg.cn/large/008i3skNly1gui6bxgxpgj61140u0q7f02.jpg)

确实有这个文件!

同时我们发现,使用的加密算法为rsa,其实还有一种dsa加密算法,两种算法的默认密钥文件不一样.

我们尝试获取.ssh文件下的id_rsa私钥文件文件

`command=/home/mowree/.ssh/id_rsa`

注意:直接显示时可能会导致文件格式有问题,可以使用快捷键ctrl+u查看原码获取正确的文件格式

![截屏2021-09-16 上午11.56.56](https://tva1.sinaimg.cn/large/008i3skNgy1guibz014grj61140u0wq602.jpg)

我们把私钥拷贝到id_rsa文件中,记得调整文件的权限

![截屏2021-09-16 上午11.59.59](https://tva1.sinaimg.cn/large/008i3skNly1guic28ctsgj60l6058gm702.jpg)

`ssh mowree@10.0.0.37 -i id_rsa`

我们尝试通过密钥验证进行登录

![截屏2021-09-16 下午12.01.04](https://tva1.sinaimg.cn/large/008i3skNly1guic3actrcj60kw02u3yz02.jpg)

很可惜,我们需要输入加密私钥的密码.

没办法,我们只能通过密码爆破啦~

#### John爆破

我们这里使用一个工具——`john`.这是一款极为强大的工具,用于在已知字典中碰撞密码破解hash等

要想使用它,我们还得先将id_rsa文件转换为他可以理解的格式

使用`/usr/share/john/ssh2john.py id_rsa > hash`将id_rsa文件转换为john可以理解的格式并输出到hash文件中

接下来我们使用强大的john结合rockyou.txt文件进行破解

`john --wordlist=<pathtodic> hash`

![截屏2021-09-16 下午5.29.52](https://tva1.sinaimg.cn/large/008i3skNly1guillfv6w8j61140a40w502.jpg)



很快就破解出来了,密码为`unicorn`

接下来我们就可以愉快的使用密钥验证进行登录啦~

![截屏2021-09-16 下午5.31.10](https://tva1.sinaimg.cn/large/008i3skNly1guilmrlwqhj60z204owfn02.jpg)

### 提权

老样子,一上来进行内核漏洞、sudo权限、suid文件的扫描

很可惜,都没有发现...

不要灰心,我们介绍一种新方法

查看计划任务`crontab -l`

这个有什么用呢?

计划任务——通常是管理员自动执行的脚本,我们可以通过修改计划任务执行脚本的内容获取权限~

![截屏2021-09-17 下午1.02.50](https://tva1.sinaimg.cn/large/008i3skNly1gujjhum5t4j60fq020aa402.jpg)

不过很可惜,没有计划任务...

那这可怎么办呢!

提权的方式大多都源自于配置的错误与高权限文件的修改.

我们不妨找一找有哪些文件是我们可以写的呢~

`find / -writable 2>/dev/null | grep -v /proc | grep -v /run | grep -v /sys`

使用`-writable`参数寻找可写入的文件,使用`grep -v`过滤三个不常用的系统文件夹.

![截屏2021-09-17 下午1.08.01](https://tva1.sinaimg.cn/large/008i3skNly1gujjn92vc8j60ie0x0aeb02.jpg)

发现了吗?我们可以修改/etc/passwd文件!!

我们查看一下

![截屏2021-09-17 下午1.08.41](https://tva1.sinaimg.cn/large/008i3skNly1gujjnxqnmrj60ow02074k02.jpg)

果然是可写的!

这意味着什么~~

#### /etc/passwd

![截屏2021-09-17 下午1.16.18](https://tva1.sinaimg.cn/large/008i3skNly1gujjvwx34oj613o0o0thq02.jpg)

我们先来了解一下`/etc/passwd`的内容.这里存放着所有linux账号的信息和密码,但是出于系统安全性的考虑,所有的密码都被`x`所替换,而真正的密码存在`/etc/shadow`中.

这是否就意味着我们无法知道密码呢?不一定.

我们可以把`x`替换为密码的密文,系统在检测时会优先选择passwd文件中的密码,即shadow中此账户的密码不生效.

我们使用`openssh passwd -1`生成密码,写入`/etc/passwd`文件中root账户的x位置,然后使用su登陆~

![截屏2021-09-17 下午1.20.17](https://tva1.sinaimg.cn/large/008i3skNly1gujk00agzpj60lm056mxv02.jpg)

![截屏2021-09-17 下午1.26.15](https://tva1.sinaimg.cn/large/008i3skNly1gujk69stt7j60t6018t8x02.jpg)

![截屏2021-09-17 下午1.26.33](https://tva1.sinaimg.cn/large/008i3skNly1gujk6j2c6yj60iq03qmxm02.jpg)

到此,我们成功获取root权限

PWN!

## 总结

我们通过新工具fping进行主机发现,经过nmap的端口扫描发现22ssh和80http服务.

在http服务的默认界面中,我们获得的信息很少,于是我们进行目录爆破,发现evil.php

怀疑evil.php是命令执行或文件包含后门,我们使用ffuf进行参数爆破,发现文件包含漏洞

通过php封装器,我们读取到了php文件,尝试写webshell,但是失败了

我们读还取了/etc/passwd文件,发现用户mowree,使用ssh -v进行详细查看,发现支持密钥认证

我们尝试读取.ssh/authorized_keys文件,发现存在此文件,并且加密方式为rsa,于是我们读取id_rsa文件,获取密钥

使用密钥时,发现需要先输入密钥的保护密码,于是我们使用ssh2john.py脚本将id_rsa文件转化为john能识别的格式,并且使用john进行破解,最后成功破解密码

然后我们顺利登陆,获得普通用户权限,进行基础的提权尝试都没有成功,于是我们使用find命令查找可写文件,发现/etc/passwd文件是可以写入的.于是我们通过openssl生成加密密文,修改root的密码,成功获得root权限!

## 附录

