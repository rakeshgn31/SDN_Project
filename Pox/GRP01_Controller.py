from pox.core import core
from pox.lib.util import dpid_to_str
from pox.forwarding.l2_learning import LearningSwitch
from GRP01_Firewall import Firewall

log = core.getLogger()

# Delay packet flooding until the topology stabilises for sometime
n_pkt_flood_delay = 0

class Controller(object):
	def __init__(self):
		core.openflow.addListeners(self)

	def _handle_ConnectionUp(self, event):
				
		data_path_id = dpid_to_str(event.dpid)[15]
		log.info("Handling the connection up event for DPID : %s" %data_path_id)
		if (data_path_id == "1" | data_path_id == "2" | data_path_id == "3" | data_path_id == "4" | data_path_id == "5"):
			LearningSwitch(event.connection, False)
		elif (data_path_id == "6"):
			log.info("Invoking Firewall 1")
			
		elif (data_path_id == "7"):
			log.info("Invoking Firewall 2")
		elif (data_path_id == "8"):
			log.info("Call Load balanacer 1")
		elif (data_path_id == "9"):
			log.info("Call Load balanacer 2")
		elif (data_path_id == "10"):
			log.info("Call IDS")
		elif (data_path_id == "11"):
			log.info("Call NAPT")

# This is the start point for the controller
def launch():
	log.info("Starting the controller")
	core.registerNew(Controller)