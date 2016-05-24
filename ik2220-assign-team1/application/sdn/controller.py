from pox.core import core
from pox.lib.util import dpid_to_str
from pox.forwarding.l2_learning import LearningSwitch
from firewall import firewall

log = core.getLogger()

class Controller(object):

        def __init__(self):
                core.openflow.addListeners(self)

        def _handle_ConnectionUp(self, event):

                data_path_id = dpid_to_str(event.dpid)
                log.debug("Handling the connection up event for DPID : %s" %data_path_id)
                if (data_path_id == "00-00-00-00-02-01" or data_path_id == "00-00-00-00-02-02" or data_path_id == "00-00-00-00-02-03" or data_path_id == "00-00-00-00-02-04" or data_path_id == "00-00-00-00-02-05"):
                        LearningSwitch(event.connection, False)
                elif (data_path_id == "00-00-00-00-02-06"):
                        log.debug("Invoking Firewall 1")
                        firewall(event.connection, False, 1)
                elif (data_path_id == "00-00-00-00-02-07"):
                        log.debug("Invoking Firewall 2")
                        firewall(event.connection, False, 2)

# This is the start point for the controller
def launch():

        log.debug("Starting the controller")
        core.registerNew(Controller)
