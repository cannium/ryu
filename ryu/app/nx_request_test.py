import gevent
import struct

from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser
from ryu.base import app_manager
from ryu.ofproto.ofproto_parser import MsgBase, msg_pack_into, msg_str_attr
from ryu.lib import mac
from ryu.lib.ofctl_v1_0 import actions_to_str
from ryu.ofproto import ether


class NX(app_manager.RyuApp):
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        }

    def __init__(self, *args, **kwargs):
        super(NX, self).__init__(*args, **kwargs)

    @staticmethod
    def _make_command(table, command):
        return table << 8 | command

    def send_flow_mod(self, dp, command, rule, actions=None):
        flow_mod = dp.ofproto_parser.NXTFlowMod(datapath=dp,
            cookie=0, command=command, idle_timeout=0, hard_timeout=0,
            priority=0x1, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_NONE,
            flags=0, rule=rule, actions=actions)
        dp.send_msg(flow_mod)

    def add_flow(self, dp, rule, actions):
        command = self._make_command(0, dp.ofproto.OFPFC_ADD)
        self.send_flow_mod(dp, command, rule, actions)

    def test(self, dp):
        rule = nx_match.ClsRule()
        rule.set_dl_type(ether.ETH_TYPE_IPV6)
        ipv6_src = struct.pack('!4I', 0x1, 0x2, 0x3, 0x4 )
        rule.set_ipv6_src( ipv6_src )

        actions = []
        actions.append(
            dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER))
        self.add_flow(dp, rule, actions)

    def test_view(self, dp):
        rule = nx_match.ClsRule()
        request = dp.ofproto_parser.NXFlowStatsRequest(datapath = dp,
                flags = 0, out_port = dp.ofproto.OFPP_NONE,
                match_len = 0, table_id = 0xff)
        dp.send_msg(request)
        

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.test(ev.dp)
            self.test_view(ev.dp)

    @handler.set_ev_cls(ofp_event.EventNXFlowStatsReply, handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        print '******************'

        for body in ev.msg.body:
            print 'cookie', hex(body.cookie)
            print 'duration', str(body.duration_sec) +'.'+ str(body.duration_nsec)
            print 'table_id', body.table_id
            print 'n_packets', body.packet_count
            print 'n_bytes', body.byte_count
            print 'idle_age', body.idle_age
            print 'priority', body.priority
            for field in body.fields:
                print 'nxm_header', hex(field.nxm_header)
                try:
                    print 'value', hex(field.value)
                except:
                    print 'value', ''.join(chr( ord(c) + ord('0')) 
                                                for c in field.value)
            print actions_to_str(body.actions)

        print '******************'
