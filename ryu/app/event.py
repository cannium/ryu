# try out ryu's event mechanism

from ryu.base import app_manager
from ryu.controller import event, handler

class Hehe(app_manager.RyuApp):

    class Event_1(event.EventBase):
        def __init__(self):
			super(Hehe.Event_1, self).__init__()
            self.msg = 'event 1'

    def __init__(self):
        super(Hehe, self).__init__()
#		app_manager.register_app(self)
        self.event = Hehe.Event_1()
        self.register_observer(Hehe.Event_1, self.name)
        print 'my name is ', self.name

    def ping(self):
        self.send_event_to_observers(self.Event_1())
        print 'pinginginging...'

    @handler.set_ev_cls(Hehe.Event_1)
    def pong(self, event):
        print 'Got ya', event.msg
		

#h = Hehe()
#h.ping()
