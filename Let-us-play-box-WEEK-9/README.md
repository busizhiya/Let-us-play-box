# **第九周**

**靶机名称**:vulnhub------**Vikings: 1**

**靶机链接**:https://www.vulnhub.com/entry/vikings-1,741/

**难度**:**CTF**

**攻击机**:Kali Linux

**使用工具**:steghide、binwalk

**强烈推荐教程**:https://pqy.h5.xeknow.com/s/2svbaU

![推广](https://tva1.sinaimg.cn/large/008i3skNly1gyov699rnlj30ku112goe.jpg)

## 信息收集

`sudo arp-scan -l`

![截屏2021-09-29 下午6.23.08](https://tva1.sinaimg.cn/large/008i3skNly1guxo7jtjejj610c0aeju702.jpg)

靶机ip:10.0.0.12

`sudo nmap -p22,80 10.0.0.12`

![截屏2021-09-29 下午6.24.35](https://tva1.sinaimg.cn/large/008i3skNly1guxo8bddyej60us0b40ui02.jpg)

`sudo nmap -p22,80 -sC -sV 10.0.0.12`

![截屏2021-09-29 下午6.24.57](https://tva1.sinaimg.cn/large/008i3skNly1guxo8picfvj611k0j6gq602.jpg)

最基本的22ssh+80http服务,我们去浏览器看看吧

## web页面

![截屏2021-09-29 下午6.26.57](https://tva1.sinaimg.cn/large/008i3skNly1guxoatotvvj61160u0jw802.jpg)	一时间好像找不到什么有用的信息

### 目录爆破

​	`dirsearch  -u "http://10.0.0.12/site"`

![截屏2021-09-30 下午8.59.52](https://tva1.sinaimg.cn/large/008i3skNly1guyyc9eyrxj60zs0lmq8602.jpg)

好像没有什么很有用的信息?

我们再用`dirb http://10.0.0.12`扫描一下

![截屏2021-09-30 下午9.00.50](https://tva1.sinaimg.cn/large/008i3skNly1guyyd8ylypj60so0jqjw702.jpg)

还是没有什么东西?!

我们再试试`gobuster dir -u http://10.0.0.12/site -x txt,html,php -w /usr/share/seclists/Discovery/Web-Content/common.txt`

这次换了个字典,使用seclist下的字典进行爆破试试?

![截屏2021-09-30 下午9.03.33](https://tva1.sinaimg.cn/large/008i3skNly1guyyg1umgmj61140u0gra02.jpg)

终于!我们发现了一点不一样!

`war.txt`,来查看一下吧~

![截屏2021-09-30 下午9.04.46](https://tva1.sinaimg.cn/large/008i3skNly1guyyhczlxtj61140u0jth02.jpg)

我们再转到`war-is-over`目录看看

![截屏2021-09-30 下午9.05.26](https://tva1.sinaimg.cn/large/008i3skNly1guyyi1iv8jj61140u0tps02.jpg)

发现了大量的加密字符串,看起来有点像......base64!

我们去试试吧~

使用我们之前推荐的神器网站CyberChef

![截屏2021-10-10 下午9.39.44](https://tva1.sinaimg.cn/large/008i3skNly1gvajovurewj61d00u0k0d02.jpg)

奇怪,怎么是像乱码一样的东西呢?

## 奇怪的字符

我们看到开头的几个字符,`PK`,有点像是一个文件头.

我们都知道,有些时候文件头表明了文件的类型!

那我们怎么得知这看似乱码的字符其实是有意义的信息呢?

我们可以通过信息熵的方式分析!

使用模块Entropy进行熵分析.

![截屏2021-09-30 下午9.23.58](https://tva1.sinaimg.cn/large/008i3skNly1guyz1dcekfj61a00u0dnr02.jpg)

分析得出的数值越高,就说明文件内容越可能是经过压缩/加密后的信息!

看来可能确实是经过压缩或加密的内容了!

我们使用模块`Detect File Type`进行文件类型的识别

![截屏2021-09-30 下午9.39.09](https://tva1.sinaimg.cn/large/008i3skNly1guyzidsczcj61a00u00zw02.jpg)

看来是PKZIP格式的压缩包,我们把他导出,进行解压

![截屏2021-10-10 下午4.00.19](https://tva1.sinaimg.cn/large/008i3skNly1gva9vp7b0zj61140u077o02.jpg)



需要密码?看来我们需要使用John进行密码爆破.

在此之前,我们需要先把zip文件通过zip2john转换为john能识别的格式

`zip2john viking.zip > hash`

![截屏2021-10-10 下午4.04.01](https://tva1.sinaimg.cn/large/008i3skNly1gva9zhgzmej61140u0ady02.jpg)

然后使用`john --wordlist=~/tools/dict/rockyou.txt hash`破解密码

成功破解!密码`ragnarok123`

再进行解压,获得了一张图片?似乎没有什么肉眼可见的信息...

![截屏2021-10-10 下午4.05.10](https://tva1.sinaimg.cn/large/008i3skNly1gvaa0oak3cj61140u0gr202.jpg)

## 隐写术!

我们知道,这是一台CTF风格的靶机,在CTF比赛中,往往会有隐写术这一隐藏信息的方法,我们这里介绍两款工具进行隐写信息的探测与提取

第一款工具——`steghide`

`steghide info king`,使用info参数查看文件信息,并探测是否有隐藏数据

![截屏2021-10-10 下午4.09.20](https://tva1.sinaimg.cn/large/008i3skNly1gvaa50kwsvj60r6084gmu02.jpg)

可以看到,这里真的有嵌入的数据,但是需要密码?

不是吧!又要密码?!

而且有个问题,这个密码可不能通过john进行破解了,只能通过隐写工具进行测试.难道要我们写个shell脚本手动爆破密码吗?!

肯定不行!

这里,我们介绍第二款工具——`binwalk`

这款工具的原理是通过二进制的方式读取数据,并发现特殊文件格式的标志,从而发现嵌入的文件

使用`binwalk -B king`进行分析

![截屏2021-10-10 下午9.31.57](https://tva1.sinaimg.cn/large/008i3skNly1gvajgqm52bj61k609qq5h02.jpg)

可以看到,其中嵌入了一个文件,文件名为user.

虽然压缩包被加密了,但是如果嵌入的文件内容没有被加密,我们可以直接提取出来!

使用`binwalk -e king`提取嵌入的文件

![截屏2021-10-10 下午9.36.43](https://tva1.sinaimg.cn/large/008i3skNly1gvajlml1wpj61l40p879w02.jpg)`//FamousBoatbuilder_floki@vikings`                        
`//f@m0usboatbuilde7 `

看来这一应该就隐藏着用户名与密码了

看,第一行这么长?这能是用户名吗?

emmmm,要不我们试试下划线后面的`floki`作为用户名?

`//`一般来说代表单行注释的意思,应该不是内容的一部分.

我们尝试把第二行当作密码,使用ssh进行登录

`floki/f@m0usboatbuilde7`

成功登陆!

## 提权

![截屏2021-10-10 下午10.41.16](https://tva1.sinaimg.cn/large/008i3skNly1gvalgtau9rj61140u0gro02.jpg)

先查看一下`history`,没有任何发现.阅读`readme.txt`文件,里面描述了一段故事.但总结来说,我们需要通过造船找到`ragnar`

进一步观察,发现了`boat`文本文件,我们查看一下.

![截屏2022-01-24 下午1.29.34](https://tva1.sinaimg.cn/large/008i3skNly1gyop7xuxsdj31140u0jtl.jpg)

可以发现,其中提示找到可打印字符,`num=第29个质数`,然后进行`collatz-conjecture`转换.

这是什么?根本看不懂!

别着急,我们一个一个来.

### 1.质数(欧拉筛法)

引入一道信息学奥林匹克竞赛题,"请在1秒钟内计算1*10^9次方以内的质数并输出"

乍一看是不是是傻眼了,别着急,其实也有简单的方法,百度搜索“第二十九个质数”即可.

但是不要小看OI人,这里我们用欧拉筛法进行计算.具体有关欧拉筛法的原理请百度~

```c++
#include <iostream>
using namespace std;
#define MAX 1000
bool check[MAX+5]={false,};
int Prime[MAX+5]={0,};
int cnt=0;
void oula()
{
	for(int i = 2;i <= MAX;i++)
	{
		if(!check[i]) 
		{
			//记录,第X个质数是i
			Prime[++cnt]=i;
		}
		for(int j = 1;j <= cnt && i*Prime[j] <= MAX;j++)
		{
			check[i*Prime[j]] = true;
			if(i%Prime[j]==0) break;
		}
	}

}

int main()
{
	oula();
	int n = 29;
	cout<<"第"<<n<<"个质数是"<<Prime[n]<<endl;
	return 0;
}
```

![截屏2022-01-24 下午1.55.23](https://tva1.sinaimg.cn/large/008i3skNly1gyopyambm1j31a8060wft.jpg)

我们获得了结果——`109`

### 2.模拟(考拉兹)

我们有万能的百度.经过搜索,我们发现`collatz-conjecture`(考拉兹猜想)其实就是冰雹猜想.

![截屏2022-01-24 下午1.32.30](https://tva1.sinaimg.cn/large/008i3skNly1gyopaicwbfj31ni0cuq6c.jpg)

我们猜测,会不会要将`num`作为第一个正整数x进行考拉兹变换呢?其中会产生很多数字,但我们只需要关注可打印字符即可!

我们使用python进行编程模拟:如果是奇数就`乘三加一`,偶数就`除二`

```python
num = 109
while num != 1 :
  print(num)
  if num%2==0:
    num /= 2
  else :
    num *= 3
    num += 1
```

模拟写好了,我们可以获得过程中的所有数字.但是我们怎么才能判断并转化为可打印字符呢?

### 3.ASCII编码

有的同学又蒙了,这是啥?	不要怕,不会就百度,这是网安人必备的技能!

![截屏2022-01-24 下午2.05.36](https://tva1.sinaimg.cn/large/008i3skNly1gyoq8yu8doj319u0f4gpm.jpg)

在`[32,126]`范围中,都是可打印字符,我们可以使用python函数`chr`进行转化.

![截屏2022-01-24 下午2.10.22](https://tva1.sinaimg.cn/large/008i3skNly1gyoqe10h0pj31tl0u0wh6.jpg)

我们获得了一串神秘字符——`mR)|>^/Gky[gz=\.F#j5P(`

回到`home`目录,发现了用户`ragnar`,猜测应该就是使用这一串字符登陆`ragnar`账号了.

![截屏2022-01-24 下午2.13.26](https://tva1.sinaimg.cn/large/008i3skNly1gyoqh2m5rvj30ge0a2q3l.jpg)

但是这个终端不是很好看,我们使用ssh本地登录到ragnar账户去.

`ssh ragnar@127.0.0.1`

`bash`

![截屏2022-01-24 下午2.14.37](https://tva1.sinaimg.cn/large/008i3skNly1gyoqifldbvj31h70u0aim.jpg)



呀?很奇怪?为什么一登录就要我们为sudo输入密码呢?

### 4.登录自动执行?

观察到登录自动执行命令的奇怪操作,我们查看一下主目录的文件.

![截屏2022-01-24 下午2.19.22](https://tva1.sinaimg.cn/large/008i3skNly1gyoqnh7n9uj31140u0n1e.jpg)

尝试使用`sudo -l`,发现ragnar没有权限...

首先,我们获取了user flag,然后我们查看了`.bashrc`和`.profile`这两个文件.由于在登陆bash终端后,bash会自动以shell脚本的模式执行这里面的配置文件.通过`grep sudo`过滤有关sudo的内容.



果然发现了奇妙的地方!!会自动执行`sudo python3 /usr/local/bin/rpyc_classic.py`指令

我们先看一看这个文件的内容,发现看不懂...

没事~我们执行一下试试吧~

执行`python3 /usr/local/bin/rpyc_classic.py`指令,发现提示端口已被占用?

![截屏2022-01-24 下午3.12.17](https://tva1.sinaimg.cn/large/008i3skNly1gyos6birh3j317u0boq7d.jpg)

我们使用`ps -aux` 指令查看是不是该程序已经启动了.

![截屏2022-01-24 下午3.13.08](https://tva1.sinaimg.cn/large/008i3skNly1gyos76v3ybj31g4028dgr.jpg)

很惊喜的是,该程序是由root用户启动的!看来突破口就在这里了!

### 5.rpyc执行

我们百度一下rpyc是什么,发现这是一套类似于远程调用的python库.

经过搜索之后,我们发现了rpyc的基本教程.

[附链接](https://blog.csdn.net/cybeyond_xuan/article/details/86493772)

我们得知,rpyc的,默认运行端口是18812,使用`netstat -pantu`,果真发现了仅开放在本地的rpyc服务!

![截屏2022-01-24 下午3.18.08](https://tva1.sinaimg.cn/large/008i3skNly1gyoscf9c0cj318e0dw432.jpg)

接下来,我们在靶机上使用python3利用rpyc执行命令.

![截屏2022-01-24 下午3.21.06](https://tva1.sinaimg.cn/large/008i3skNly1gyosfirz4vj31k60as44s.jpg)

引入rpyc库,连接本地rpyc服务端,可以通过`conn.execute`接口执行python代码,我们包含os库,执行shell命令.

看看这一长串是什么?其实这是我的id_rsa.pub,即ssh公钥.通过将我的ssh公钥加入`/root/.ssh/authorized_keys`,我们就可以实现免密登陆root账号!

![截屏2022-01-24 下午3.23.52](https://tva1.sinaimg.cn/large/008i3skNly1gyosin827aj31140u0tdj.jpg)

此处还有一种提权方法,我们已经知道了ragnar用户的密码,只需要将他加入sudo组即可!

`conn.execute('os.system("usermod -a -G sudo ragnar")')`

执行完记得退出ssh,重新登陆即可!

![截屏2022-01-24 下午3.38.31](https://tva1.sinaimg.cn/large/008i3skNly1gyosxlv7xbj30sy082gn1.jpg)

**PWN!!**成功啦!

Ps:	

​	1.此处笔者还尝试使用nc反弹shell,但是失败了.可能是由于网络原因,若大家有兴趣可以继续尝试.

​	2.此处执行代码利用了**Bash嵌套引号**的技巧,有兴趣的同学可以自行了解.

## 总结

本次靶机是一台类CTF风格的靶机,体现在其技术性操作,如“隐写术”、“编码转换”等.

但他也不失为一台有意义的靶机,其中考察了我们的代码编写能力,算法能力等.

一开始的突破较为困难,第一次目录扫描的结果令我们大失所望,就在我们以为这台靶机没有什么突破口时,我们换用了不同的工具,采用不同的字典进行重复扫描,最终才发现线索.

在线索的引导下,我们发现了一大堆经过编码的数据.通过神器“CyberChef”的帮助,我们成功地将编码转化为了一个加密的压缩包,通过john爆破出了king这张图片.

一开始我们尝试通过工具steghide反向读取图片中的数据,但是发现隐写时已经对内容进行了加密,于是我们使用工具binwalk强行提取其中的二进制数据,最终发现了user文件.

在经过简单的尝试后,我们成功一floki的身份登入靶机,并尝试常见的提权向量,未果.

在阅读readme.txt与boat文件后,我们通过“欧拉筛法查找质数”与“模拟考拉兹”成功获取了ragnar账号的密码,并登陆.

在登陆ragnar账号后发现异常状况,登陆后自动执行了一个sudo指令.通过查看~/.profile文件我们发现了rpyc文件并查阅相关资料,通过网上教程成功以root身份执行命令,最终将ragnar加入sudo组/ssh公钥加入authorized_keys,成功获得root权限.

## 附录

### 1.oula-prime.cpp

欧拉筛法计算质数

### 2.collatz.py

模拟“考拉兹变换“,即”冰雹猜想“

