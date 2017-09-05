from scapy.all import *
from pox.core import core
import time, os
log = core.getLogger()

a = rdpcap("ext/capture.pcapng")

class getWirelessAttr (object):
    signal = 1
    addr1 = ''
    addr2 = ''
    addr3 = ''
    rssi_threshold = 0
    status = 'connected'
    mininet_dir = ''

class _wireless (object):
            
    #@classmethod
    def __init__ (self, rssi_threshold, mininet_dir):
        getWirelessAttr.rssi_threshold = rssi_threshold
        getWirelessAttr.mininet_dir = mininet_dir
        t1 = time.time()
        for i in range(len(a)):
            cont = True
            pkt = a[i]
        #    pkt.show()
            if i == 0:
                timestamp1 = pkt.time
                timestamp2 = pkt.time
            if pkt.subtype == 8:
                while cont:
                    if (time.time() - t1 >= (timestamp2 - timestamp1)):
                        #print self.signal
                        extra = pkt.notdecoded
                        signal_strength = -(256-ord(extra[-4:-3]))
                        getWirelessAttr.signal = signal_strength
                        getWirelessAttr.addr1 = pkt.addr1
                        getWirelessAttr.addr2 = pkt.addr2
                        getWirelessAttr.addr3 = pkt.addr3
                        timestamp2 = pkt.time
                        self.do_something()
                        cont = False
                    else:
                        cont = True
            #t = a[i].fields['wlan.fc.type_subtype eq 8']
            #print t
    
    #@classmethod
    def do_something(self):
        if getWirelessAttr.addr3 == '02:00:00:00:01:00':
            if getWirelessAttr.signal < getWirelessAttr.rssi_threshold and getWirelessAttr.signal != 1:
                if getWirelessAttr.status == 'connected':
                    getWirelessAttr.status = 'disconnected'
                    #print getWirelessAttr.addr2
                    os.system('%sutil/m sta1 iw dev sta1-wlan0 disconnect' % getWirelessAttr.mininet_dir)
                    log.info("sta1 gets disconnected!")
                    os.system('%sutil/m sta1 iw dev sta1-wlan0 connect ap2' % getWirelessAttr.mininet_dir)
                    log.info("sta1 is associated to ap2!")
            
def launch (rssi_threshold, mininet_dir):
    thread = threading.Thread(target=_wireless, args=(float(rssi_threshold),mininet_dir,))
    thread.daemon = True
    thread.start()