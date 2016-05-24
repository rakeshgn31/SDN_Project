from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

# Firewall forward rules
fw1_fwd_rules = [ ('ICMP', '100.0.0.10', '*', '100.0.0.25', '*'),
				  ('ICMP', '100.0.0.11', '*', '100.0.0.25', '*'),
				  ('ICMP', '100.0.0.10', '*', '100.0.0.45', '*'),
				  ('ICMP', '100.0.0.11', '*', '100.0.0.45', '*'),
				  ('ICMP', '100.0.0.10', '*', '100.0.0.1', '*'),
				  ('ICMP', '100.0.0.11', '*', '100.0.0.1', '*'),				  
				  ('ICMP', '100.0.0.25', '*', '100.0.0.10', '*'),
				  ('ICMP', '100.0.0.25', '*', '100.0.0.11', '*'),
				  ('ICMP', '100.0.0.45', '*', '100.0.0.10', '*'),
				  ('ICMP', '100.0.0.45', '*', '100.0.0.11', '*'),
				  ('ICMP', '100.0.0.1', '*', '100.0.0.10', '*'),
				  ('ICMP', '100.0.0.1', '*', '100.0.0.11', '*'),				  
				  ('UDP', '100.0.0.10', '*', '100.0.0.25', '53'),
				  ('UDP', '100.0.0.11', '*', '100.0.0.25', '53'),
				  ('UDP', '100.0.0.25', '53', '100.0.0.10', '*'),
				  ('UDP', '100.0.0.25', '53', '100.0.0.11', '*'),
				  ('UDP', '100.0.0.10', '*', '100.0.0.1', '*'),
				  ('UDP', '100.0.0.11', '*', '100.0.0.1', '*'),
				  ('UDP', '100.0.0.1', '*', '100.0.0.10', '*'),
				  ('UDP', '100.0.0.1', '*', '100.0.0.11', '*'),
				  ('TCP', '100.0.0.10', '*', '100.0.0.45', '80'),
				  ('TCP', '100.0.0.11', '*', '100.0.0.45', '80'),
				  ('TCP', '100.0.0.45', '80', '100.0.0.10', '*'),
				  ('TCP', '100.0.0.45', '80', '100.0.0.11', '*'),
				  ('TCP', '100.0.0.10', '*', '100.0.0.1', '*'),
				  ('TCP', '100.0.0.11', '*', '100.0.0.1', '*'),
				  ('TCP', '100.0.0.1', '*', '100.0.0.10', '*'),
				  ('TCP', '100.0.0.1', '*', '100.0.0.11', '*') ]
				  
fw2_fwd_rules = [ ('ICMP', '100.0.0.1', '*', '100.0.0.10', '*'),
				  ('ICMP', '100.0.0.1', '*', '100.0.0.11', '*'),
				  ('ICMP', '100.0.0.1', '*', '100.0.0.25', '*'),
				  ('ICMP', '100.0.0.1', '*', '100.0.0.45', '*'),
				  ('ICMP', '100.0.0.10', '*', '100.0.0.1', '*'),
				  ('ICMP', '100.0.0.11', '*', '100.0.0.1', '*'),
				  ('ICMP', '100.0.0.25', '*', '100.0.0.1', '*'),
				  ('ICMP', '100.0.0.45', '*', '100.0.0.1', '*'),				  
				  ('UDP', '100.0.0.1', '*', '100.0.0.25', '53'),
				  ('UDP', '100.0.0.1', '*', '100.0.0.10', '*'),
				  ('UDP', '100.0.0.1', '*', '100.0.0.11', '*'),
				  ('UDP', '100.0.0.25', '53', '100.0.0.1', '*'),
				  ('UDP', '100.0.0.10', '*', '100.0.0.1', '*'),
				  ('UDP', '100.0.0.11', '*', '100.0.0.1', '*'),				  
				  ('TCP', '100.0.0.1', '*', '100.0.0.45', '80'),
				  ('TCP', '100.0.0.1', '*', '100.0.0.10', '*'),
				  ('TCP', '100.0.0.1', '*', '100.0.0.11', '*'),
				  ('TCP', '100.0.0.45', '80', '100.0.0.1', '*'),
				  ('TCP', '100.0.0.10', '*', '100.0.0.1', '*'),
				  ('TCP', '100.0.0.11', '*', '100.0.0.1', '*'), ]

class firewall (object):
  """
	This class contains most of the Learning Switch class code and 
	additional code to filter the traffic as per the requirement
  """
  
  def __init__ (self, connection, transparent, fwIdentifier):

    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0
	
    # Identifier to identify which firewall to invoke
	self.fwIdentifier = fwIdentifier

  def _handle_PacketIn (self, event):
  
    """
    Handle the incoming packets and filter the traffic
	according to the firewall rules	
    """
    packet = event.parsed

	# Handle the packet and decide whether to flood/forward/drop
    self.macToPort[packet.src] = event.port

    if not self.transparent:
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop()
        return

    if packet.dst.is_multicast:
		flood()
    else:
		if packet.dst not in self.macToPort:
			flood("Port for %s unknown -- flooding" % (packet.dst,))
		else:
			port = self.macToPort[packet.dst]
			if port == event.port:
				log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
					% (packet.src, packet.dst, dpid_to_str(event.dpid), port))
				drop(10)
				return
        
		# Check which firewall to run
		bForward = False
		if self.fwIdentifier == '1':
			log.debug("Running rules of Firewall 1")
			bForward = runFirewall1()
		if self.fwIdentifier == '2':
			log.debug("Running rules of Firewall 2")
			bForward = runFirewall2()
        
		# If the incoming packet does not satisfy any forward rules
		# then, drop the packet and return immediately
		if bForward == False:
			drop()
			return

		# Finally, if everything passes then install the forwarding rule
        forward()

	# Floods the packet
    def flood (message = None):
		""" Floods the packet """
		msg = of.ofp_packet_out()
		if time.time() - self.connection.connect_time >= _flood_delay:
			# Only flood if we've been connected for a little while...

			if self.hold_down_expired is False:
				# Oh yes it is!
				self.hold_down_expired = True
				log.info("%s: Flood hold-down expired -- flooding", dpid_to_str(event.dpid))

			if message is not None: log.debug(message)
			#log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
			# OFPP_FLOOD is optional; on some switches you may need to change
			# this to OFPP_ALL.
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		else:
			pass
			#log.info("Holding down flood for %s", dpid_to_str(event.dpid))

		msg.data = event.ofp
		msg.in_port = event.port
		self.connection.send(msg)

	# Drops the packet
    def drop (duration = None):
		"""
		Drops this packet and optionally installs a flow to continue
		dropping similar ones for a while
		"""
		if duration is not None:
			if not isinstance(duration, tuple):
				duration = (duration,duration)
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(packet)
			msg.idle_timeout = duration[0]
			msg.hard_timeout = duration[1]
			msg.buffer_id = event.ofp.buffer_id
			self.connection.send(msg)
		elif event.ofp.buffer_id is not None:
			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id
			msg.in_port = event.port
			self.connection.send(msg)
    
	# Return True(Forward), if the incoming packet is an ARP packet
	def handleARPPackets():
		if packet.find('arp') is not None:
			return True

	# Forwards the packet
	def forward():
		log.debug("installing flow rule for %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, port))
		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet, event.port)
		msg.idle_timeout = 10
		msg.hard_timeout = 30
		msg.actions.append(of.ofp_action_output(port = port))
		msg.data = event.ofp
		self.connection.send(msg)
		
	# Checks the incoming packet against the firewall rules of FW1 (near Public zone)
    def runFirewall1():
	  
		# Handle the ARP Packets
		if handleARPPackets() == True:
			return True;
				
		if packet.find(pkt.ipv4) is not None:
			ip = packet.find(pkt.ipv4)
			src_ip_addr=ip.srcip
			dst_ip_addr=ip.dstip
			log.debug("IP Source: %s" % src_ip_addr)
			log.debug("IP Dest: %s" % dst_ip_addr)
		
			# Handle the ICMP packets
			icmp = packet.find('icmp')
			if icmp is not None:						
				if (icmp.type == 0 or icmp.type == 8):
					return True
			
			# Handle the UDP packets
			if packet.find('udp') is not None:
				log.debug("Firewall 1 - Found UDP packet")
				udp_src_port = packet.find('udp').srcport
				udp_dst_port = packet.find('udp').dstport
				for (protocol, srcIP,srcPort,dstIP,dstPort) in fw1_fwd_rules:   
					if(protocol == 'UDP'):
						if(str(src_ip_addr) == srcIP and str(dst_ip_addr) == dstIP):
							if(srcPort == '*'):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == udp_dst_port):
									return True
							elif(srcPort != '*' and srcPort == udp_src_port):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == udp_dst_port):
									return True
		
			# Handle the TCP packets
			if packet.find('tcp') is not None:
				log.debug("Firewall 1 - Found TCP packet")
				tcp_src_port = packet.find('tcp').srcport
				tcp_dst_port = packet.find('tcp').dstport
				for (protocol, srcIP,srcPort,dstIP,dstPort) in fw1_fwd_rules:   
					if(protocol == 'TCP'):
						if(str(src_ip_addr) == srcIP and str(dst_ip_addr) == dstIP):
							if(srcPort == '*'):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == tcp_dst_port):
									return True
							elif(srcPort != '*' and srcPort == tcp_src_port):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == tcp_dst_port):
									return True	

		return False

	# Checks the incoming packet against the firewall rules of FW2 (near Private zone)
    def runFirewall2():

		# Handle the ARP packets
		if handleARPPackets() == True:
			return True
			
		if packet.find(pkt.ipv4) is not None:
			ip = packet.find(pkt.ipv4)
			src_ip_addr=ip.srcip
			dst_ip_addr=ip.dstip
			log.debug("IP Source: %s" % src_ip_addr)
			log.debug("IP Dest: %s" % dst_ip_addr)
			
			# Handle the ICMP packets
			icmp = packet.find('icmp')
			if icmp is not None:
				if icmp.type == 0:
					log.debug("Firewall 2 - ICMP ECHO REPLY")
					for (protocol,srcIP,srcPort,dstIP,dstPort) in fw2_fwd_rules:  
					if(protocol == 'ICMP'):
						if(str(src_ip_addr) == srcIP and str(dst_ip_addr) == dstIP):
							return True
				if icmp.type == 8:
					log.debug("Firewall 2 - ICMP ECHO REQUEST")
					for (protocol,srcIP,srcPort,dstIP,dstPort) in fw2_fwd_rules: 
						if(str(src_ip_addr) == '100.0.0.1'):
							return True
		
			# Handle the UDP packets
			if packet.find('udp') is not None:
				log.debug("Firewall 2 - Found UDP packet")
				udp_src_port = packet.find('udp').srcport
				udp_dst_port = packet.find('udp').dstport
				for (protocol, srcIP,srcPort,dstIP,dstPort) in fw2_fwd_rules:   
					if(protocol == 'UDP'):
						if(str(src_ip_addr) == srcIP and str(dst_ip_addr) == dstIP):
							if(srcPort == '*'):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == udp_dst_port):
									return True
							elif(srcPort != '*' and srcPort == udp_src_port):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == udp_dst_port):
									return True
			
			# Handle the TCP packets
			if packet.find('tcp') is not None:
				log.debug("Firewall 2 - Found TCP packet")
				tcp_src_port = packet.find('tcp').srcport
				tcp_dst_port = packet.find('tcp').dstport
				for (protocol, srcIP,srcPort,dstIP,dstPort) in fw2_fwd_rules:   
					if(protocol == 'TCP'):
						if(str(src_ip_addr) == srcIP and str(dst_ip_addr) == dstIP):
							if(srcPort == '*'):
								if(dstPort == '*'):
									# New TCP connection from outside should be dropped
									if(str(src_ip_addr) != '100.0.0.1' and packet.find('tcp').ack == 0):
										return False
								elif(dstPort != '*' and dstPort == tcp_dst_port):
									return True
							elif(srcPort != '*' and srcPort == tcp_src_port):
								if(dstPort == '*'):
									return True
								elif(dstPort != '*' and dstPort == tcp_dst_port):
									return True	

		return False
