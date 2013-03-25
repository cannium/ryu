'''
Topology discovery using LLDP
written by can.( can [AT] canx.me )
'''

import gevent
import logging
import time
import struct

from ryu.base import app_manager
from ryu.lib.packet import lldp, ethernet, packet
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.controller import event, dpset, handler, ofp_event
from ryu.ofproto import ether, nx_match

LOG = logging.getLogger(__name__)

class LinkEvent(event.EventBase):
    '''
        The event raises from Discovery,
        used to other applications some link goes up/down
    '''
    def __init__(self, link, linkUp = True):
        super(LinkEvent, self).__init__()
        self.linkUp = linkUp
        self.linkDown = not linkUp
        self.link = link

class Switch(object):
    def __init__(self, datapath):
        # dp is defined in ryu.controller.controller.Datapath
        self.dp = datapath  
        self.links = []

class Link(object):
    def __init__(self, switch1, port1, switch2, port2):
        self.switch1 = switch1
        self.port1 = port1
        self.switch2 = switch2
        self.port2 = port2
        self.updateTime = time.time()

    def __eq__(self, other):
        if self.switch1 == other.switch1 and \
            self.port1 == other.port1 and \
            self.switch2 == other.switch2 and \
            self.port2 == other.port2:
            return True

        if self.switch1 == other.switch2 and \
            self.port1 == other.port2 and \
            self.switch2 == other.switch1 and \
            self.port2 == other.port1:
            return True

        return False


# dpid -> switch object
switchOfDpid = {}

class Discovery(app_manager.RyuApp):
    _EVENTS = [LinkEvent]
    _CONTEXTS = {'dpset' : dpset.DPSet}

    LLDP_SEND_PERIOD = 10
    LLDP_CHECK_PERIOD = 20
    LLDP_TTL = 30
    CHASSIS_ID_PREFIX = 'dpid:'


    def __init__(self, *args, **kwargs):
        super(Discovery, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        gevent.spawn(self.send_lldp_loop)
        gevent.spawn(self.check_timeout_loop)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def dpEventHandler(self,event):
        dp = event.dp
        if event.enter:
            print dp.id, 'joined'
            newSwitch = Switch(dp)
            switchOfDpid[dp.id] = newSwitch
#            print switchOfDpid

            rule = nx_match.ClsRule()
            rule.set_dl_type(ether.ETH_TYPE_LLDP)
            rule.set_dl_dst(lldp.LLDP_MAC_NEAREST_BRIDGE)
            ofproto = dp.ofproto
            ofproto_parser = dp.ofproto_parser
            output = ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                    max_len = 65535)
            actions = [output]
            dp.send_flow_mod(rule = rule, cookie = 0, 
                           command = ofproto.OFPFC_ADD,
                           idle_timeout = 0, hard_timeout = 0,
                           actions = actions)
        else:
            print dp.id, 'has left'
            if dp.id:
                # sometimes a dp.id == None comes with event.enter == False
                del switchOfDpid[dp.id]
            # TODO raise link events?

    def check_timeout_loop(self):
        while True:
            print 'checking...'
            current = time.time()
            for _k, switch in switchOfDpid.iteritems():
                for l in switch.links:
                    if l.updateTime + Discovery.LLDP_TTL < current:
                        self.update(switch.dp.id, l, linkUp = False)
                        print 'link removed', l
                        switch.links.remove(l)

            gevent.sleep(Discovery.LLDP_CHECK_PERIOD)

    def calc_sleep_time(self, before, after):
        if after - before < Discovery.LLDP_SEND_PERIOD:
            return Discovery.LLDP_SEND_PERIOD - (after - before)
        else:
            return 0

    def send_lldp(self, datapath):
        tlv_chassis_id = lldp.ChassisID(
                subtype = lldp.ChassisID.SUB_LOCALLY_ASSIGNED, 
                chassis_id = Discovery.CHASSIS_ID_PREFIX + \
                            dpid_to_str(datapath.id))
        tlv_ttl = lldp.TTL(ttl = Discovery.LLDP_TTL)
        tlv_end = lldp.End()
        for port_no, port in datapath.ports.iteritems():
            if port_no > datapath.ofproto.OFPP_MAX:
                continue
            pkt = packet.Packet()
            eth_packet = ethernet.ethernet(dst = lldp.LLDP_MAC_NEAREST_BRIDGE,
                                src = port.hw_addr,
                                ethertype = ether.ETH_TYPE_LLDP)
            pkt.add_protocol(eth_packet)
            
            tlv_port_id = lldp.PortID(
                    subtype = lldp.PortID.SUB_INTERFACE_NAME,
                    port_id = str(port_no) )
            all_tlv = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
            lldp_packet = lldp.lldp(tlvs = all_tlv)
            pkt.add_protocol(lldp_packet)

            pkt.serialize()
                                
            self.packetOut(datapath, port_no, pkt)

    def packetOut(self, datapath, port_no, pkt):
        '''
            datapath is the object, not ID or some number
        '''
        actions = [datapath.ofproto_parser.OFPActionOutput(port_no)]
        datapath.send_packet_out(in_port = datapath.ofproto.OFPP_NONE, \
                                actions = actions, data = pkt.data)
            

    def send_lldp_loop(self):
        while True:
            print 'looping...'
            before = time.time()
            for _k ,switch in switchOfDpid.iteritems():
                self.send_lldp(switch.dp)
            after = time.time()
            
            gevent.sleep( self.calc_sleep_time(before, after))

    def lldp_parse(self, data):
        # because there's a try...except covering this function,
        # error check not needed
        
        pkt = packet.Packet(data)
        eth = pkt.next()
        assert eth.dst == lldp.LLDP_MAC_NEAREST_BRIDGE
        assert eth.ethertype == ether.ETH_TYPE_LLDP
        lldp_pkt = pkt.next()
                
        tlv_chassis_id = lldp_pkt.tlvs[0]
        assert tlv_chassis_id.subtype == lldp.ChassisID.SUB_LOCALLY_ASSIGNED
        chassis_id = tlv_chassis_id.chassis_id
        assert chassis_id.startswith(Discovery.CHASSIS_ID_PREFIX)
        # strip 'dpid:' from chassis_id and get dpid
        src_dpid = str_to_dpid(chassis_id[len(Discovery.CHASSIS_ID_PREFIX):])

        port_id = lldp_pkt.tlvs[1]
        assert port_id.subtype == lldp.PortID.SUB_INTERFACE_NAME
        port_no = int( port_id.port_id)
        
        return src_dpid, port_no


    def update(self, dpid, link, linkUp = True):
        switch = switchOfDpid[dpid]

        for l in switch.links:
            if l == link:
                l.updateTime = link.updateTime
                return

        linkEvent = LinkEvent(link, linkUp = linkUp)
        self.send_event_to_observers( linkEvent )
        print 'raised linkEvent'

        switch.links.append(link)


    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packetInHandler(self, event):
        msg = event.msg
        try:
            src_dpid, src_port_no = self.lldp_parse(msg.data)
        except:
            return

        incoming_dpid = msg.datapath.id
        incoming_port_id = msg.in_port
        print 'src', src_dpid, src_port_no, 'in', incoming_dpid, incoming_port_id
        link = Link(src_dpid, src_port_no, incoming_dpid, incoming_port_id)
        # insert or update switch
        self.update(src_dpid, link, linkUp = True)
        self.update(incoming_dpid, link, linkUp = True)
        
                
