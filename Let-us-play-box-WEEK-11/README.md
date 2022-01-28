# 第11周

**靶机名称**:**Billu_b0x**

**靶机链接**:https://download.vulnhub.com/billu/Billu_b0x.zip

**难度**:*Mideum*

**攻击机**:Kali Linux

**使用工具**:dirsearch,burpsuite

**强烈推荐教程**:https://pqy.h5.xeknow.com/s/2svbaU

![推广](https://tva1.sinaimg.cn/large/008i3skNly1gyov699rnlj30ku112goe.jpg)

## 主机发现

发现局域网内靶机ip:`sudo arp-scan -l --interface=eth0`

![截屏2022-01-26 下午2.50.52](https://tva1.sinaimg.cn/large/008i3skNly1gyr2sr94z9j314u0aqgp8.jpg)

ip:`172.20.10.10`

`sudo nmap -p- 172.20.10.10`

`sudo nmap -p22,80 -sC -sV 172.20.10.10`

日常扫描端口与服务~

![截屏2022-01-26 下午2.52.19](https://tva1.sinaimg.cn/large/008i3skNly1gyr2ua0x18j311v0u0do7.jpg)

经典的22+80端口,加下来开启对web服务的探索吧!

## web页面



![截屏2022-01-26 下午2.54.09](https://tva1.sinaimg.cn/large/008i3skNly1gyr2wfoy5oj31c00u079n.jpg)

进入页面,发现需要我们进行登陆~

既然有交互,我们就尝试对密码与用户名进行sql注入!

在经过一番的手工尝试后,我们发现这个注入点并没有那么容易攻破.

遇事不决...SQLMAP!

我们使用burp拦截请求包,并将请求包的POST参数加上`*`号,存到`burp.pack`文件中.

使用`sqlmap -r burp.pack --batch --random-agent --level=3 `进行测试



![截屏2022-01-26 下午3.07.27](https://tva1.sinaimg.cn/large/008i3skNly1gyr3a12r26j31c00u0n3h.jpg)

## 提权

## 总结

在这此打靶机过程中,我们遇到了许多熟悉的漏洞,但是都不太好利用.突破的方式有千万种,但那一种都离不开信息收集!在此次使用了如burpsuite自动化sqli漏洞测试、burpsuite手动检查数据包等方式进行突破,这考验的就是细心程度!同时,上传漏洞要求我们绕过检测,学习不同的过检测手段十分重要!

## 附录

