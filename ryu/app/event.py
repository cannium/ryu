import gevent

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller.handler import set_ev_cls


TEST_EVENT_EV_DISPATCHER = "test_event"


class EventTest(event.EventBase):
    def __init__(self, msg):
        super(EventTest, self).__init__()
        self.msg = msg


class TestEvent(app_manager.RyuApp):
    def __init__(self):
        super(TestEvent, self).__init__()
#        self.name = 'test_event'
        print self.name
        self.register_observer(EventTest, self.name)
        gevent.spawn_later(0, self._send_event_loop)

    def _send_event_loop(self):
        i = 0
        while True:
            #print 'loop'
            self.send_event_to_observers(EventTest(i))
            i += 1
            gevent.sleep(1)

    @set_ev_cls(EventTest, TEST_EVENT_EV_DISPATCHER)
    def _recv_handler(self, ev):
        print 'recv:', ev.msg

'''
class Test2(app_manager.RyuApp):
    def __init__(self):
        super(Test2, self).__init__()
        print '~~~~~~heheheheheehe~~~~~'


class ATest3(app_manager.RyuApp):
    def __init__(self):
        super(ATest3, self).__init__()
        print '~~~~~~hahahahahahaha~~~~~'
'''
