# HTB Knife

## 端口扫描&服务扫描

一开始进行了最简单的端口扫描,发现22ssh与80web服务.



使用nikto对web界面进行,发现PHP 8.0-dev.使用searchsploit很轻松的就发现了现成的exp.使用exp获得了一个反弹shell,获得了user-flag.我们的用户为james,uid1000.使用sudo -l发现可以使用sudo权限NO PASSWD执行knife指令,由于使用帮助很长,找了很久发现了exec参数,可以执行脚本.本来以为是shell脚本,没想到报错了,依照提示使用-VVV参数,详细列出执行过程,发现了ruby环境,我们把ruby反弹命令写入文件,使用sudo knife exec <file>成功提权,反弹了root-shell.
    总体来说,我们利用了现成的exp打开了立足点,通过sudo -l发现了提权的利用点,仔细分析knife命令,最后反弹了ruby-shell,成功获得root权限