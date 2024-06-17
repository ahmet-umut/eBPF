from socket import socket as so
import socket
from random import randrange as rr

pds=1	# Packet Data Size
pcif=1	# Packet count in files. each file has pcif packets
r=1	# Number of files to be sent

ip="172.22.101.100"
port=1111

def getpacket():
	return bytearray(rr(256) for i in range(pds))

soc = so(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(r):
	for j in range(pcif):
		pd=getpacket()
		print([int(d) for d in pd])
		soc.sendto(pd, (ip,port))
# soc.sendto(b"\0", (ip,port))
soc.close()