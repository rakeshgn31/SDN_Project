from pox.core import core
from pox.lib.util import dpid_to_str
from pox.forwarding.l2_learning import LearningSwitch
from Firewall import firewall

log = core.getLogger()

class Controller(object):

	def __init__(self):
		core.openflow.addListeners(self)

	def _handle_ConnectionUp(self, event):
				
		data_path_id = dpid_to_str(event.dpid)
		log.debug("Handling the connection up event for DPID : %s" %data_path_id)
		if (data_path_id == "0000000000000201" | data_path_id == "0000000000000202"):
			LearningSwitch(event.connection, False)
		elif (data_path_id == "0000000000000203"):
			log.debug("Invoking Firewall 1")
			firewall(event.connection, False, 1)
		elif (data_path_id == "0000000000000204"):
			log.debug("Invoking Firewall 2")
			firewall(event.connection, False, 2)

# This is the start point for the controller
def launch():

	log.debug("Starting the controller")
	core.registerNew(Controller)
