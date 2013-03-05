# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import dpkt
import gevent
import gflags
import logging
import struct
import time
from dpkt.ethernet import Ethernet


from ryu import exception as ryu_exc
from ryu.base import app_manager
from ryu.controller import (dpset,
                            handler,
                            link_set,
                            ofp_event)
from ryu.controller.link_set import (Link,
                                     LinkSet)
from ryu.lib.packet import lldp
from ryu.lib import mac
from ryu.lib.dpid import (dpid_to_str,
                          str_to_dpid)
from ryu.lib.packet.lldp import (ChassisID,
                          End,
                          PortID,
                          TTL)
from ryu.ofproto import ether, nx_match


LOG = logging.getLogger(__name__)


FLAGS = gflags.FLAGS
gflags.DEFINE_multistring('discovery_install_flow', True,
                          'disocvery: explicitly install flow entry '
                          'to send lldp packet to controller')
gflags.DEFINE_multistring('discovery_explicit_drop', True,
                          'disocvery: explicitly drop lldp packet in')


def port_is_down(dp, port):
    return bool((port.config & dp.ofproto.OFPPC_PORT_DOWN) |
                (port.state & dp.ofproto.OFPPS_LINK_DOWN))


class PortData(object):
    def __init__(self, is_down, data):
        super(PortData, self).__init__()
        self.is_down = is_down
        self.data = data
        self.timestamp = None

        # a counter, larger than Discovery.LINK_LLDP_DROP
        # means link is broken
        self.sent = 0

    def lldp_sent(self):
        self.timestamp = time.time()
        self.sent += 1

    def lldp_received(self):
        self.sent = 0

    def lldp_dropped(self):
        return self.sent

    def clear_timestamp(self):
        self.timestamp = None

    def set_down(self, is_down):
        self.is_down = is_down

    def __str__(self):
        return 'PortData<%s, %s, %d>' % (self.is_down,
                                         self.timestamp,
                                         self.sent)


class PortSet(dict):
    """
    dict: (dp, port_no) -> PortData(timestamp, aux)
    slimed down version of OrderedDict as python 2.6 doesn't support it.
    """
    _PREV = 0
    _NEXT = 1
    _KEY = 2

    def __init__(self):
        super(PortSet, self).__init__()
        self.__root = root = []         # sentinel node
        root[:] = [root, root, None]    # [_PREV, _NEXT, _KEY]
                                        # doubly linked list
        self.__map = {}

    def _remove_key(self, key):
        link_prev, link_next, key = self.__map.pop(key)
        link_prev[self._NEXT] = link_next
        link_next[self._PREV] = link_prev

    def _append_key(self, key):
        root = self.__root
        last = root[self._PREV]
        last[self._NEXT] = root[self._PREV] = self.__map[key] = [last, root,
                                                                 key]

    def _prepend_key(self, key):
        root = self.__root
        first = root[self._NEXT]
        first[self._PREV] = root[self._NEXT] = self.__map[key] = [root, first,
                                                                  key]

    def _move_last_key(self, key):
        self._remove_key(key)
        self._append_key(key)

    def _move_front_key(self, key):
        self._remove_key(key)
        self._prepend_key(key)

    def add_port(self, dp, port_no, is_down, data):
        key = (dp, port_no)
        if key not in self:
            self._prepend_key(key)
            self[key] = PortData(is_down, data)
        else:
            self[key].is_down = is_down

    def lldp_sent(self, dp, port_no):
        key = (dp, port_no)
        port_data = self[key]
        port_data.lldp_sent()
        self._move_last_key(key)
        return port_data

    def lldp_received(self, dp, port_no):
        key = (dp, port_no)
        self[key].lldp_received()

    def move_front(self, dp, port_no):
        key = (dp, port_no)
        port_data = self.get(key, None)
        if port_data is not None:
            port_data.clear_timestamp()
            self._move_front_key(key)

    def set_down(self, dp, port_no, is_down):
        key = (dp, port_no)
        port_data = self[key]
        port_data.set_down(is_down)
        port_data.clear_timestamp()
        if not is_down:
            self._move_front_key(key)

    def get_port(self, dp, port_no):
        key = (dp, port_no)
        return self[key]

    def _del_port_key(self, key):
        del self[key]
        self._remove_key(key)

    def del_port(self, dp, port_no):
        key = (dp, port_no)
        self._del_port_key(key)

    def get_dp_port(self, dp):
        return [key_port_no for (key_dp, key_port_no) in self if key_dp == dp]

    def __iter__(self):
        root = self.__root
        curr = root[self._NEXT]
        while curr is not root:
            yield curr[self._KEY]
            curr = curr[self._NEXT]

    def clear(self):
        for node in self.__map.itervalues():
            del node[:]
        root = self.__root
        root[:] = [root, root, None]
        self.__map.clear()
        dict.clear(self)

    def items(self):
        'od.items() -> list of (key, value) pairs in od'
        return [(key, self[key]) for key in self]

    def iteritems(self):
        'od.iteritems -> an iterator over the (key, value) pairs in od'
        for k in self:
            yield (k, self[k])


class LLDPPacket(object):
    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'      # uint32_t
    PORT_ID_SIZE = 4

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        tlv_chassis_id = ChassisID(subtype=ChassisID.SUB_LOCALLY_ASSIGNED,
                                   chassis_id=LLDPPacket.CHASSIS_ID_FMT %
                                   dpid_to_str(dpid))

        tlv_port_id = PortID(subtype=PortID.SUB_PORT_COMPONENT,
                             port_id=struct.pack(LLDPPacket.PORT_ID_STR,
                                                 port_no))

        tlv_ttl = TTL(ttl=ttl)
        tlv_end = End()

        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_data = lldp.lldp(tlvs=tlvs)

        eth = Ethernet(dst=lldp.LLDP_MAC_NEAREST_BRIDGE, src=dl_addr,
                       type=ether.ETH_TYPE_LLDP, data=lldp_data)
        return str(eth)         # serialize it

    class LLDPUnknownFormat(ryu_exc.RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_parse(data):
        eth = Ethernet(data)
        if not (eth.dst == lldp.LLDP_MAC_NEAREST_BRIDGE and
                eth.type == lldp.ETH_TYPE_LLDP):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown dst mac(%s) or type(%s)' % (eth.dst, eth.type))
        lldp_data = eth.lldp

        chassis_id = lldp_data.tlvs[0]
        if chassis_id.subtype != ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % chassis_id.subtype)
        chassis_id = chassis_id.chassis_id
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])

        port_id = lldp_data.tlvs[1]
        if port_id.subtype != PortID.SUB_PORT_COMPONENT:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id subtype %d' % port_id.subtype)
        port_id = port_id.port_id
        if len(port_id) != LLDPPacket.PORT_ID_SIZE:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id %d' % port_id)
        (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)

        return src_dpid, src_port_no


class Discovery(app_manager.RyuApp):
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'link_set': LinkSet,
                 }

    # TODO:XXX what's appropriate parameter? adaptive?
    # in seconds
    DEFAULT_TTL = 120   # unused. ignored.
    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, mac.DONTCARE, 0))

    def __init__(self, *args, **kwargs):
        super(Discovery, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.link_set = kwargs['link_set']
        # two parameters from command line
        self.install_flow = kwargs.get('install_flow',
                                       FLAGS.discovery_install_flow)
        self.explicit_drop = kwargs.get('explicit_drop',
                                        FLAGS.discovery_explicit_drop)

        self.port_set = PortSet()
        self.lldp_event = gevent.event.Event()
        self.link_event = gevent.event.Event()
        self.is_active = True
        self.threads = []
        self.threads.append(gevent.spawn_later(0, self.lldp_loop))
        self.threads.append(gevent.spawn_later(0, self.link_loop))

    def close(self):
        self.is_active = False
        self.lldp_event.set()
        self.link_event.set()
        # gevent.killall(self.threads)
        gevent.joinall(self.threads)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def dp_handler(self, ev):
        LOG.debug('dp_handler %s %s', ev, ev.enter_leave)
        dp = ev.dp
        if ev.enter_leave:
            if self.install_flow:
                rule = nx_match.ClsRule()
                rule.set_dl_dst(lldp.LLDP_MAC_NEAREST_BRIDGE)
                rule.set_dl_type(lldp.ETH_TYPE_LLDP)
                ofproto = dp.ofproto
                ofproto_parser = dp.ofproto_parser
                output = ofproto_parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, max_len=self.LLDP_PACKET_LEN)
                actions = [output]
                dp.send_flow_mod(
                    rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                    idle_timeout=0, hard_timeout=0, actions=actions)

    def _port_added(self, dp, port):
        port_no = port.port_no
        lldp_data = LLDPPacket.lldp_packet(
            dp.id, port_no, port.hw_addr, self.DEFAULT_TTL)
        is_down = port_is_down(dp, port)
        self.port_set.add_port(dp, port_no, is_down, lldp_data)
        LOG.debug('_port_added %s %s, %s',
                  dpid_to_str(dp.id), port_no, is_down)

    @handler.set_ev_cls(dpset.EventPortAdd, dpset.DPSET_EV_DISPATCHER)
    def port_add_handler(self, ev):
        dp = ev.dp
        port = ev.port
        if dp.is_reserved_port(port.port_no):
            return
        self._port_added(dp, port)
        self.lldp_event.set()

    def _link_down(self, dp, port_no):
        dpid = dp.id
        try:
            dst = self.link_set.port_deleted(dpid, port_no)
        except KeyError:
            return

        dst_dp = self.dpset.get(dpid)
        if dst_dp is not None:
            self.port_set.move_front(dst_dp, dst.port_no)

    @handler.set_ev_cls(dpset.EventPortDelete, dpset.DPSET_EV_DISPATCHER)
    def port_del_handler(self, ev):
        dp = ev.dp
        port_no = ev.port.port_no
        if dp.is_reserved_port(port_no):
            return
        LOG.debug('port_del %s %d', dp, port_no)
        self.port_set.del_port(dp, port_no)
        self._link_down(dp, port_no)
        self.lldp_event.set()

    @handler.set_ev_cls(dpset.EventPortModify, dpset.DPSET_EV_DISPATCHER)
    def port_modify_handler(self, ev):
        dp = ev.dp
        port = ev.port
        port_no = port.port_no
        if dp.is_reserved_port(port_no):
            return
        is_down = port_is_down(dp, port)
        self.port_set.set_down(dp, port_no, is_down)
        if is_down:
            self._link_down(dp, port_no)
        self.lldp_event.set()

    @staticmethod
    def _drop_packet(msg):
        if msg.buffer_id != 0xffffffff:  # TODO:XXX use constant instead of -1
            msg.datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        # LOG.debug('packet in ev %s msg %s', ev, ev.msg)
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except dpkt.UnpackError as e:
            LOG.debug('error in unpack packet %s', e)
        except LLDPPacket.LLDPUnknownFormat as e:
            # This handler can receive all the packtes which can be
            # not-LLDP packet. Ignore it silently
            return
        else:
            if not self.link_set.update_link(src_dpid, src_port_no,
                                             msg.datapath.id, msg.in_port):
                # reverse link is not detected yet.
                # So schedule the check early because it's very likely it's up
                try:
                    self.port_set.lldp_received(msg.datapath, msg.in_port)
                except KeyError:
                    # There are races between EventOFPPacketIn and
                    # EventDPPortAdd. So packet-in event can happend before
                    # port add event. In that case key error can happend.
                    LOG.debug('KeyError')
                else:
                    self.port_set.move_front(msg.datapath, msg.in_port)
                    self.lldp_event.set()
            if self.explicit_drop:
                self._drop_packet(msg)

    def send_lldp_packet(self, dp, port_no):
        try:
            port_data = self.port_set.lldp_sent(dp, port_no)
        except KeyError as e:
            # port_set can be modified during our sleep in self.lldp_loop()
            LOG.debug('port_set %s key error %s', self.port_set, e)
            return
        if port_data.is_down:
            return
        actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
        dp.send_packet_out(actions=actions, data=port_data.data)
        # LOG.debug('lldp sent %s %d', dpid_to_str(dp.id), port_no)

    def lldp_loop(self):
        while self.is_active:
            self.lldp_event.clear()

            now = time.time()
            timeout = None
            ports_now = []
            ports = []
            # LOG.debug('port_set %s', self.port_set)
            for (key, data) in self.port_set.items():
                if data.timestamp is None:
                    ports_now.append(key)
                    continue

                expire = data.timestamp + self.LLDP_SEND_PERIOD_PER_PORT
                if expire <= now:
                    ports.append(key)
                    continue

                timeout = expire - now
                break

            for (dp, port_no) in ports_now:
                self.send_lldp_packet(dp, port_no)
            for (dp, port_no) in ports:
                self.send_lldp_packet(dp, port_no)
                gevent.sleep(self.LLDP_SEND_GUARD)      # don't burst

            if timeout is not None and ports:
                timeout = 0     # We have already slept
            # LOG.debug('lldp sleep %s', timeout)
            self.lldp_event.wait(timeout=timeout)

    def link_loop(self):
        while self.is_active:
            self.link_event.clear()

            now = time.time()
            deleted = []
            for (link, timestamp) in self.link_set.items():
                # TODO:XXX make link_set ordereddict?
                # LOG.debug('link %s timestamp %d', link, timestamp)
                if timestamp + self.LINK_TIMEOUT < now:
                    src = link.src
                    src_dp = self.dpset.get(src.dpid)
                    if src_dp is not None:
                        port_data = self.port_set.get_port(src_dp,
                                                           src.port_no)
                        LOG.debug('port_data %s', port_data)
                        if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
                            deleted.append(link)

            for link in deleted:
                self.link_set.link_down(link)
                LOG.debug('delete link %s', link)

                dst = link.dst
                rev_link = Link(dst, link.src)
                if rev_link not in deleted:
                    # It is very likely that the reverse link is also
                    # disconnected. Check it early.
                    expire = now - self.LINK_TIMEOUT
                    self.link_set.rev_link_set_timestamp(rev_link, expire)
                    dst_dp = self.dpset.get(dst.dpid)
                    if dst_dp is not None:
                        self.port_set.move_front(dst_dp, dst.port_no)
                        self.lldp_event.set()

            self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)


class LinkEventWatcher(app_manager.RyuApp):
    _CONTEXTS = {
        # this is needed to generate LinkEvent
        'link_set': LinkSet,
        }

    @handler.set_ev_cls(link_set.LinkEvent, link_set.LINK_SET_EV_DISPATCHER)
    def link_event_handler(self, ev):
        LOG.info('LinkEvent %s', ev)
