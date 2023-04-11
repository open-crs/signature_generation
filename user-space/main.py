import nsocket
import struct


NETLINK_USER = 17

netlink_socket = nsocket.NetlinkSocket(NETLINK_USER)
netlink_socket.sendto('Hello from user-space!')

print(netlink_socket.recvfrom(1024))