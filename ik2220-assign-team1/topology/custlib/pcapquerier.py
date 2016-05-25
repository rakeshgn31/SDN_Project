"""
Instance of this class creates links that is available in iproute2 toolkit between a mininet node such as a switch and the kernel of the host machine/VM that
mininet runs on. While one end (virtual ethernet) of the link is connected to the mininet node, the other end is another veth generated in the kernel waiting to 
be connected to anything.

One use-case is to develop an NFV middlebox using Click modular router (CMR) and connect the other end of the link. 
Tested with userspace CMR. 
    
Author: Huseyin Kayahan
"""

import dpkt
import time
import socket

class PcapQuerier:
 	
	def __init__(self, String):
        #Wait a bit for pcap to be dumped
		global f
	        time.sleep(2)
        	f = open(String,"rb")
        	self.pcap=dpkt.pcap.Reader(f)
        
	def httpContainsMetURI(self,list):
          	ctr=0
		for ts, buf in self.pcap:
		    eth = dpkt.ethernet.Ethernet(buf)
		    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
			    ip = eth.data
		    	    if ip.p == dpkt.ip.IP_PROTO_TCP:
			  	tcp = ip.data 
			  	if tcp.dport == 80 and len(tcp.data) > 0:
		                  http = dpkt.http.Request(tcp.data)
                          	  MetURI=http.method + ' ' + http.uri
				  for string in list:
                             	      if MetURI == string:
					 ctr+=1	
                return ctr>0         

	
	def srcIP(self,string):
		 for ts, buf in self.pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                            ip = eth.data
			    ip_src_addr = str(socket.inet_ntoa(ip.src))
			    if ip_src_addr != string:
				return False
		 return True

	def stop(self):
		global f
	   	f.close()		
		

