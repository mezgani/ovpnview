import socket
import re

class connexion:
    """class connexion that create a socket, and connects to management openvpn server"""
    def __init__(self, hostname, port, password, request, version):
       self.hostname=hostname
       self.port=port
       self.password=password
       self.request=request
       self.version=version

    def interact(self):
        """function that interacte with the server and try to get out some data"""
        try:
           sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
           sock.connect((self.hostname,self.port))

           data = sock.recv(1024)
           sock.send(self.password)
           sock.send('\r\n')
           data = sock.recv(4096)
           line=re.findall('SUCCESS:',data)
           if line != []:
                sock.send('\r\n')
                sock.recv(1024)

                sock.send(self.request)
                sock.send('\r\n')
                data = sock.recv(40960)
                if self.request.find('kill')!=0:
                   data += sock.recv(40960)

                sock.send('exit')
                sock.send('\r\n')
                sock.close()
                return data

           else:
                pass

        except Exception, e:
                 raise(str(e))
