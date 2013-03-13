'''
Topology discovery using LLDP
written by can.( can [AT] canx.me )
'''

import gevent
import logging
import time

from ryu.base import app_manager
from ryu.lib.packet import lldp
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.controller import event, dpset

class LinkEvent(event.EventBase):
    def __init__(self, link, linkUp = True):
        super(LinkEvent, self).__init__()
        self.linkUp = linkUp
        self.linkDown = not linkUp
        self.link = link

class Discovery(app_manager.RyuApp):
    _EVENTS = [LinkEvent]
    _CONTEXTS = {'dpset' : dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(Discovery, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']

