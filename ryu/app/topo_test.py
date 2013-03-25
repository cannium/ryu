from ryu.base import app_manager
from ryu.app import topo_discovery
from ryu.controller import handler, dpset

class Test(app_manager.RyuApp):
    _CONTEXTS = {'topo_discovery' : topo_discovery.Discovery,
                'dpset' : dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)
        self.discover = kwargs['topo_discovery']

    @handler.set_ev_cls(topo_discovery.LinkEvent)
    def handler(self, event):
        print 'link up?', event.linkUp
        link = event.link
        print 'link', link.switch1, link.port1, link.switch2, link.port2
