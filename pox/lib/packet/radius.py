import struct
from packet_utils import *
from udp import *

from packet_base import packet_base

class radius(packet_base):
    "Extensible Authentication Protocol packet"
    MIN_LEN = 20
    
    mac = []
    mac_ = []
    name = []
    name_ = []
    rule = []
    rule1 = {}
    
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13
    RESERVED = 255
    
    USER_NAME_TYPE = 1
    USER_PASSWORD_TYPE = 2
    CHAP_PASSWORD_TYPE = 3
    NAS_IP_ADDRESS_TYPE = 4
    NAS_PORT_TYPE = 5
    SERVICE_TYPE_TYPE = 6
    FRAMED_PROTOCOL_TYPE = 7
    FRAMED_IP_ADDRESS_TYPE = 8
    FRAMED_IP_NETMASK_TYPE = 9
    FRAMED_ROUTING_TYPE = 10
    CALLED_STATION_ID = 30
    CALLING_STATION_ID = 31
    
    RADIUS_PORT = 1812

    code_names = {ACCESS_REQUEST: "request",
                  ACCESS_ACCEPT: "accept",
                  ACCESS_REJECT: "reject",
                  ACCOUNTING_REQUEST: "acreq",
                  ACCOUNTING_RESPONSE: "acresp",
                  ACCESS_CHALLENGE: "challenge",
                  STATUS_SERVER: "statusserver",
                  STATUS_CLIENT: "statusclient",
                  RESERVED: "reserved"
    }

    type_names = { USER_NAME_TYPE : "username",
                  USER_PASSWORD_TYPE: "userpasswd",
                  CHAP_PASSWORD_TYPE: "chappasswd",
                  NAS_IP_ADDRESS_TYPE: "nasipaddr",
                  NAS_PORT_TYPE: "nasport",
                  SERVICE_TYPE_TYPE: "tos",
                  FRAMED_PROTOCOL_TYPE: "frameproto",
                  FRAMED_IP_ADDRESS_TYPE: "frameipaddr",
                  FRAMED_IP_NETMASK_TYPE: "frameipnetmask",
                  FRAMED_ROUTING_TYPE: "framerouting",
                  CALLED_STATION_ID: "calledstationid",
                  CALLING_STATION_ID: "callingstationid"
    }

    @staticmethod
    def code_name(code):
        return radius.code_names.get(code, "code%d" % code)

    @staticmethod
    def type_name(type):
        return radius.type_names.get(type, "type%d" % type)

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)
        self.prev = prev

        self.code = self.ACCESS_REQUEST
        self.id = 0
        self.length = 0
        
        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[RAD %s id=%d' % (radius.code_name(self.code), self.id)
        if hasattr(self, 'type'):
            s += ' type=%s' % (radius.type_names[self.type],)
        return s + "]"

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(eapol parse) warning EAP packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.code, self.id, self.length) \
            = struct.unpack('!BBH', raw[:self.MIN_LEN/5])

        self.hdr_len = self.length
        self.payload_len = 0
        self.parsed = True

        if self.code == self.ACCESS_REQUEST:
            (self.type,) \
                = struct.unpack('!B', raw[self.MIN_LEN:self.MIN_LEN + 1])
            # not yet implemented
        elif self.code == self.ACCESS_ACCEPT:
            (self.type,) \
                = struct.unpack('!B', raw[self.MIN_LEN:self.MIN_LEN + 1])
            # not yet implemented
        elif self.code == self.ACCESS_ACCEPT:
            self.next = None    # Success packets have no payload
        elif self.code == self.ACCESS_REQUEST:
            self.next = None    # Failure packets have no payload
        else:
            self.msg('warning unsupported EAP code: %s' %
                     (radius.code_name(self.code),))
        
        i = 0
        for pack in raw:
            (n_type,) = struct.unpack('!B', pack)
            i += 1
            if self.CALLING_STATION_ID == n_type:
                mac_ = str(raw[i+1:i+18])
                if mac_ not in self.mac and '-0' in mac_:
                    self.mac.append(mac_)
                    self.mac_.append(mac_)
                    break
                #print (str(raw[i+1:i+18]))
            #if self.CALLED_STATION_ID == n_type:
            #    print str(raw[i:i+17]) 
        nam_ = str(raw[22:25])
        if len(self.mac_) == 1:
            self.rule1[self.mac_[0]] = ''
        if len(self.mac_) == 1 and nam_ != self.rule1[self.mac_[0]] and nam_ != '':
            self.name.append(str(nam_))
            self.name_.append(nam_)
            self.rule1[self.mac_[0]] = nam_ 
     
    def hdr(self, payload):
        return struct.pack('!BBH', self.code, self.id, self.length)
