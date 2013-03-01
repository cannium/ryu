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
        self.name = 'test_event'
        gevent.spawn_later(0, self._send_event_loop)

    def _send_event_loop(self):
        i = 0
        while True:
            self.send_event_to_observers(EventTest(i))
            i += 1
            gevent.sleep(1)

    @set_ev_cls(EventTest, TEST_EVENT_EV_DISPATCHER)
    def _recv_handler(self, ev):
        print 'recv:', ev.msg
