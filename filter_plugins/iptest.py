import socket

prefix_max_map = {4: 32, 6: 128}

#TODO: IPv6 conversion
def addr2hex(address):
    addrsplit = address.split(".")
    hexaddr = 0
    addrlen = len(addrsplit)
    for i in range(0, addrlen):
        num = int(addrsplit[i])
        shiftnum = (32 - 8) - (i * 8)
        hexaddr |= (num & 0xff) << shiftnum
    return hexaddr

# TODO: IPv6 conversion
def hex2addr(hexaddr, version=4):
    addr = []
    if version == 4:
        for i in range(32 - 7, 0, -8):
            addr.append(str(((0xff << (i-1)) & hexaddr) >> (i-1)))
        return ".".join(addr)
    return 0

def mask2prefixlen(hexaddr, version):
    if not hexaddr or not version:
        return 0
    j, maxlen = 0, prefix_max_map[version]
    for i in range(maxlen - 1, -1, -1):
        j |= (0x1 << i)
        if j == hexaddr:
            return maxlen - i
    return 0

def is_addr4(addr):
    return addr.version == 4

def is_addr6(addr):
    return addr.version == 6

def is_valid_net(addr):
    return addr.netmask is not None

def get_ver(addr):
    return addr.version

def get_addr(addr):
    return hex2addr(addr.address)

def get_subnet(addr):
    if addr.netmask:
        return "%s/%s" % (hex2addr(addr.netaddr), addr.prefixlen)
    return 0

def get_mask(addr):
    return hex2addr(addr.netmask) if addr.netmask else 0

def get_cidr(addr):
    return addr.prefixlen

def is_net4(addr):
    return addr.version == 4 and is_valid_net(addr)

def is_net6(addr):
    return addr.version == 6 and is_valid_net(addr)

def is_host(addr):
    if not is_valid_net(addr):
        return False
    return addr.address != addr.broadcast and addr.address != addr.netaddr

def in_net(addr, value=None):
    if not value:
        raise ValueError("Error: Network not specified")
    if not addr.address:
        return False
    subnet = IPAddress(value)
    return (addr.address & subnet.netmask) == subnet.netaddr

def ip_add(addr, value=1):
    try:
        inc = int(value)
    except Exception:
        raise ValueError("Error: unable to convert %s to integer" % value)
    return hex2addr(addr.address + inc)

class IPAddress:
    def __init__(self, value):
        self.address = None
        self.version = None
        self.prefixlen = None
        self.netmask = 0
        self.netaddr = None

        if '/' in value:
            try:
                address = value.split('/')[0] if '/' in value else value
                self.prefixlen = int(value.split('/')[1])
            except Exception:
                address = 0
        else:
            address = value

        try:
            socket.inet_pton(socket.AF_INET, address)
            self.version = 4
            self.address = addr2hex(address)
        except Exception:
            try:
                socket.inet_pton(socket.AF_INET6, address)
                self.version = 6
                self.address = addr2hex(address)
            except Exception:
                pass

        if self.address and self.version and self.prefixlen:
            maxlen = prefix_max_map[self.version]
            if self.prefixlen >= 0 and self.prefixlen <= maxlen:
                for i in range(maxlen - 1, (maxlen - self.prefixlen) - 1, -1):
                    self.netmask |= (0x1 << i)
                self.netaddr = self.netmask & self.address
                self.broadcast = ~self.netmask | self.address
        elif mask2prefixlen(self.address, self.version):
            self.prefixlen = mask2prefixlen(self.address, self.version)


def iptest(val1, func, val2=None):
    iptest1_map = {
        'in_net': in_net,
        'add': ip_add
    }

    iptest2_map = {
        'is_addr4': is_addr4,
        'is_addr6': is_addr6,
        'is_net4': is_net4,
        'is_net6': is_net6,
        'is_host': is_host,
        'get_ver': get_ver,
        'get_addr': get_addr,
        'get_subnet': get_subnet,
        'get_mask': get_mask,
        'get_cidr': get_cidr,
    }

    addr = IPAddress(val1)
    if func in iptest1_map:
        if not val2:
            return iptest1_map[func](addr)
        else:
            return iptest1_map[func](addr, val2)
    else:
        return iptest2_map[func](addr)


def iprange_has_addr(iprangelist, value):
    addr = IPAddress(value)
    rangelo = IPAddress(iprangelist[0])
    rangehi = IPAddress(iprangelist[1])
    return rangelo.address <= addr.address <= rangehi.address

def iprange_is_valid(iprangelist, value):
    rangelo = IPAddress(iprangelist[0])
    rangehi = IPAddress(iprangelist[1])
    return bool(rangelo.address and rangehi.address)

def iprange_in_net(iprangelist, value):
    if not iprange_is_valid(iprangelist, value):
        raise ValueError("Invalid Range %s" % iprangelist)
    subnet = IPAddress(value)
    rangelo = IPAddress(iprangelist[0])
    rangehi = IPAddress(iprangelist[1])
    if not subnet.netmask:
        raise ValueError("Invalid Subnet %s" % value)
    return in_net(rangelo, value) and in_net(rangehi, value)

def iprange_split(iprangelist, value):
    return iprangelist

def iprange(iprange, func, value=None):
    iprange_map = {
        'has_addr': iprange_has_addr,
        'in_net': iprange_in_net,
        'is_valid': iprange_is_valid,
        'split': iprange_split,
    }

    if isinstance(iprange, list):
        iprangelist = iprange
    elif '-' in iprange:
        iprangelist = [i.strip() for i in iprange.split('-')]
    elif 'to' in iprange:
        iprangelist = [i.strip() for i in iprange.split('to')]
    elif func == 'is_valid':
        return False
    else:
        raise ValueError("Invalid Range %s" % iprange)

    return iprange_map[func](iprangelist, value)


class FilterModule(object):
    def filters(self):
        filters = {
            'iptest': iptest,
            'iprange': iprange,
        }

        return filters
