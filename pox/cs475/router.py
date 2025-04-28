from pox.core import core
import pox.openflow.libopenflow_01 as of
import struct
import time
import binascii
import threading

log = core.getLogger()
ICMP_PROTOCOL = 1
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV4 = 0x0800

BROADCAST_MAC = bytes([0xff]*6)

def ip2str(ip):
    return ".".join(["%i"%x for x in ip])

def ip2binarystr(ip):
    return "".join([format(x, "08b") for x in ip])

def mac2str(mac):
    return ":".join(["%02x"%x for x in mac])

def get_ip_subnet(ipcidr):
    """
    For a string of the format ip4/int (e.g. 192.168.0.50/24), 
    convert into an ip address in bytes and a subnet mask in bytes

    Parameters
    ----------
    ipcidr: str
        ip4/int (e.g. 192.168.0.50/24)
    
    Returns
    -------
    ip: bytes(4)
        IP address in binary
    subnet: bytes(4)
        Subnet mask in binary
    """
    ip, cidr = ipcidr.split("/")
    cidr = int(cidr)
    ip = bytes([int(c) for c in ip.split(".")])
    subnet = "1"*cidr + "0"*(32-cidr)
    subnet = struct.pack(">I", int(subnet, 2))
    return ip, subnet

def get_checksum(bs):
    """
    Compute the internet checksum for some bytes

    Parameters
    ----------
    bs: list of bytes
        Bytes on which to compute the checksum
    
    Returns
    -------
    Checksum
    """
    if len(bs) % 2 == 1:
        bs += bytes([0])
    shorts = struct.unpack("!" + "H"*(len(bs)//2), bs)
    c = 0
    for s in shorts:
        c = c + s
        if ( (c >> 16) & 0xffff) > 0:
            c = (c & 0xffff) + 1
    c = (~c) & 0xffff
    return c


class RouterSwitch:
    def __init__ (self, connection, ip, subnet, links):
        """
        Constructor for our router switch

        Parameters
        ----------
        connection:
            Pox connection object
        ip: bytes(4)
            IPv4 address
        subnet: bytes(4)
            Subnet mask
        links: {(ip, subnet):set([(ip, subnet), ...])}
            Links to neighboring routers
        """
        self.connection = connection
        connection.addListeners(self)
        self.mac = struct.pack("!Q", connection.dpid)[2:]
        self.ip = ip
        self.subnet = subnet
        log.debug("New router with ip {}, subnet mask {}, mac {}".format(ip2str(self.ip), ip2str(self.subnet), mac2str(self.mac)))

        self.route_table = []
        self.route_table_lock = threading.Lock()
        for (ip, subnet) in links:
            self.route_table.append(dict(ip=ip, subnet=subnet, next=ip, dist=1))
        self.route_table.append(dict(ip=self.ip, subnet=self.subnet, next=self.ip))

        self.mac2port = {}
        self.mac2port_lock = threading.Lock()
        
        self.arp = {}
        self.arp_queue = {}
        self.arp_lock = threading.Lock()

    def print_arp_table(self):
        """
        A method that prints the ARP table of this router, for debugging
        """
        with self.arp_lock:
            s = "------------------------\nARP Table for {}, {}:\n".format(ip2str(self.ip), ip2str(self.subnet))
            for ip, mac in self.arp.items():
                ip_str = ".".join(["%i"%x for x in ip])
                mac_str = ":".join(["%02x"%x for x in mac])
                s += f"\t{ip_str} -> {mac_str}\n"
            s += "------------------------"
            log.debug(s)

    def _handle_PacketIn(self, event):
        """
        Handle all incoming packets at this switch
        """
        ## Step 1: Unpack information about the packet
        src_port = event.port
        try:
            packet = event.parsed.pack() # This contains all bytes of the packet from the ethernet header up
        except:
            #log.debug("Failed to process packet {}".format(event))
            return

        ## TODO: Fill this in.  You'll want lots of helper instance methods!



class RouterConnector:
    """
    Waits for OpenFlow switches to connect and makes them our switches
    """
    def __init__(self, filename):
        with open(filename) as fin:
            import json
            netinfo = json.load(fin)
        self.routers = netinfo["routers"]
        self.links = {}
        for r1, r2 in netinfo["links"]:
            r1 = get_ip_subnet(r1)
            r2 = get_ip_subnet(r2)
            if not r1 in self.links:
                self.links[r1] = set([])
            if not r2 in self.links:
                self.links[r2] = set([])
            self.links[r1].add(r2)
            self.links[r2].add(r1)
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        ip, subnet = get_ip_subnet(self.routers[event.dpid-1]["ip"])
        RouterSwitch(event.connection, ip, subnet, self.links[(ip, subnet)])


def launch(filename):
    core.registerNew(RouterConnector, filename)