# Me-and-my-girl-friend-1

**靶机名称**:vulnhub---**me-and-my-girl-friend-1**

**靶机链接**:https://www.vulnhub.com/entry/me-and-my-girlfriend-1,409/

**难度**:*Beginner*

**攻击机**:Kali Linux

**使用工具**:

## 主机发现

![截屏2021-08-30 上午11.41.12](https://tva1.sinaimg.cn/large/008i3skNgy1gtynzesgcoj60z40c278j02.jpg)

![截屏2021-08-30 上午11.40.54](https://tva1.sinaimg.cn/large/008i3skNgy1gtynz69otlj612s0gejxe02.jpg)

## web页面

### 我从哪里来

![截屏2021-08-30 上午11.41.43](https://tva1.sinaimg.cn/large/008i3skNgy1gtynzxy5plj61140u0tbp02.jpg)

需要本地访问?我们尝试能不能绕过它

开启burpsuite,拦截请求包,发送到Repeater中进行测试

我们尝试修改Referer,X-Forwarded-For以混淆服务端的来源检测

经过尝试,只需要修改xff即可

![截屏2021-08-30 下午12.10.59](https://tva1.sinaimg.cn/large/008i3skNly1gtyoufaz00j61c00u0td802.jpg)

看到提示,修改xff?

![截屏2021-08-30 下午12.11.47](https://tva1.sinaimg.cn/large/008i3skNly1gtyov9kzdlj61c00u044c02.jpg)

注意,请求头的末尾要空两行,即两个\n

可以使用Proxy->Options->Match and Replace自动修改xff,此处不过多赘述

### 	功能探索

此处我们继续挂着burp的代理,关闭拦截,把功能点都试一试,看看会有什么发现~

![截屏2021-08-30 下午12.14.36](https://tva1.sinaimg.cn/large/008i3skNly1gtyoy6cnikj60uq09smy902.jpg)

其中“登陆”、”注册”这两个选项属实让人心动

我们先随意注册一个账号,然后登录进去,看看有什么额外的功能

![截屏2021-08-30 下午12.17.37](https://tva1.sinaimg.cn/large/008i3skNgy1gtyp1aptd6j61c80gqq5302.jpg)

wow,有个Profile的页面,点进去看看

![截屏2021-08-30 下午12.18.16](https://tva1.sinaimg.cn/large/008i3skNgy1gtyp1xntroj61bm0dg3zi02.jpg)

admin账号是我刚才随意注册的账号,密码也是admin.看来这是一个修改密码与用户名的地方~

我们回到burp,查看请求包历史![截屏2021-08-30 下午12.19.25](https://tva1.sinaimg.cn/large/008i3skNly1gtyp3506ohj61c00u0n7402.jpg)

我的天,有没有感觉令人眼花缭乱?

我们注意到POST请求,尝试sql注入无果

再看看profile和dashboard页面提交了user_id,我们尝试修改user_id,看看有什么不同?

profile的返回内容居然包含了用户名和密码,而且可以通过提交不同的user_id获得不同用户的用户名和密码!

![截屏2021-08-30 下午6.47.20](https://tva1.sinaimg.cn/large/008i3skNgy1gtz0astwj5j620e0u0agm02.jpg)

经过一番尝试,我们发现了Alice的用户名与密码

为什么是Alice?

用心的朋友可以查看一下vulnhub页面的此靶机描述

"我们的主角Bob和Alice是一对情侣.Bob发现自从Alice进了公司后有点不对劲,害怕头顶帽子变色(不是,请你调查一番"

Alice不就是我们的主人公吗~

我们尝试用`alice/4lic3`登陆ssh

成功啦~![截屏2021-08-30 下午6.50.49](https://tva1.sinaimg.cn/large/008i3skNgy1gtz0efqtnfj627i0rutiy02.jpg)



一开始使用`ls`发现目录为空,我们又使用`ls -la`详细显示所有文件,发现隐藏文件夹`.my_secret`,进入后发现flag,获得flag~

**Flag1:  `gfriEND{2f5f21b2af1b8c3e227bcf35544f8f09}`**

接下来我们就要尝试提权啦~



## 提权

![截屏2021-08-30 下午6.53.14](https://tva1.sinaimg.cn/large/008i3skNgy1gtz0gxv82xj61l409wgpg02.jpg)

老套的`sudo -l`,发现可以sudo使用php,那么这就好办啦,用php反弹一个shell吧~

`sudo /usr/bin/php -r "system('/bin/bash');" `

成功获得root权限~

![截屏2021-08-30 下午6.55.18](https://tva1.sinaimg.cn/large/008i3skNgy1gtz0j3et1dj627o0mc0zk02.jpg)

**PWN**!获得root~

**Flag2 : `gfriEND{56fbeef560930e77ff984b644fde66e7}`**

## 总结

一开始扫描发现web与ssh界面,访问web时发现只有本地可以访问,于是通过修改X-Forwarded-For头伪造本地127.0.0.1访问.

通过register功能注册账号,登录后获得更丰富的功能选项

通过profile功能的任意用户密码泄漏得到主人公alice的密码,通过ssh登陆

user-flag通过`ls -la`发现隐藏目录获得.通过`sudo -l`发现php的root权限,通过php反弹,获得root权限

注意点:此靶机的介绍给予了我们提示,平时要多留心,不能粗心大意哦~



