# Linux Local Privilege Escalation Checklist

1.`uname -an`		检查内核版本

2.`sudo -l`		检查sudo权限可执行程序

3.`find / -perm 4000 2>/dev/null`		suid文件

4.`find / -perm 2000 2>/dev/null`		sgid文件

5.`crontab -l`		查看计划任务

6.`ls -la /etc/ | grep passwd`		查看passwd写入权限

7.`ls -la /etc/ | grep shadow`		查看shadow读取权限

8.`getcap / -r 2>/dev/null`			查看capabilities文件

9.`netstat -ano | grep 127.0.0.1`	查看本地开放端口

10.`grep -R "pass" <path>`		查找某个目录下含‘pass’字眼的文件

11.尝试登陆本地数据库

12.检查`/var/backups`

13.用户名当作密码尝试登陆账号(弱凭据)

14.`find / -writable 2>/dev/null`

15.linpeas.sh脚本