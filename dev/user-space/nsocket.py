import socket
import struct
import os

"""
struct nlmsghdr {
	__u32		nlmsg_len;	 /* Length of message including header */
	__u16		nlmsg_type;	 /* Message content */
	__u16		nlmsg_flags; /* Additional flags */
	__u32		nlmsg_seq;	 /* Sequence number */
	__u32		nlmsg_pid;	 /* Sending process port ID */
};
"""

nl_nlmsghdr = "IHHII"
NLMSGHDRLEN = struct.calcsize(nl_nlmsghdr)

class NetlinkSocket:
    def __init__(self, NETLINK_USER):
        self.NETLINK_USER = NETLINK_USER
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, self.NETLINK_USER)
        self.sock.bind((0, 0))

        # 270 is SOL_NETLINK and 1 is NETLINK_ADD_MEMBERSHIP
        self.sock.setsockopt(270, 1, 31)

    def sendto(self, message):
        try:
            self.sock.sendto(self.__nlmsghdr(0,0,0,0,os.getpid()) + bytes(message, 'utf-8'), (0, 0))
        except socket.error as e:
            print('Exception: ' + e.args)

    def recvfrom(self, size):
        contents, (nlpid, nlgrps) = self.sock.recvfrom(size)
        struct.unpack("IHHII", contents[:16])
        return bytes.decode(contents[16::], 'utf-8').rstrip('\0')

    def __nlmsghdr(self, mlen,nltype,flags,seq,pid):
        """
        create a nlmsghdr
        :param mlen: length of message
        :param nltype: message content
        :param flags: additional flags
        :param seq: sequence number
        :param pid: process port id
        :returns: packed netlink msg header
        """
        return struct.pack(nl_nlmsghdr,NLMSGHDRLEN+mlen,nltype,flags,seq,pid)
    
    def close(self):
        self.sock.close()
