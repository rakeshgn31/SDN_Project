from pox.core import core
from pox.lib.util import dpid_to_str
from pox.forwarding.l2_learning import LearningSwitch

log = core.getLogger()

class Controller(object):

        def __init__(self):
                core.openflow.addListeners(self)

        def _handle_ConnectionUp(self, event):

                data_path_id = dpid_to_str(event.dpid)
                log.debug("Handling the connection up event for DPID : %s" %data_path_id)
                if (data_path_id == "00-00-00-00-02-01"):
                        LearningSwitch(event.connection, False)
               

# This is the start point for the controller
def launch():

        log.debug("Starting the controller")
        core.registerNew(Controller)