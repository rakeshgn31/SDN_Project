"""
Instance of this class creates links that is available in iproute2 toolkit between a mininet node such as a switch and the kernel of the host machine/VM that
mininet runs on. While one end (virtual ethernet) of the link is connected to the mininet node, the other end is another veth generated in the kernel waiting to 
be connected to anything.

One use-case is to develop an NFV middlebox using Click modular router (CMR) and connect the other end of the link. 
Tested with userspace CMR. 
    
Author: Huseyin Kayahan
"""

from mininet.link import Intf
from mininet.node import (Node)
from mininet.log import setLogLevel, info, error
from mininet.util import quietRun
class NFVMiddlebox:
 	
	def __init__(self,name):
        	self.name=name
	        self.localIfIndex = 0
		global localInterfaces
		global remoteInterfaces
		localInterfaces = []
		info( '*** Adding NFV Middlebox: %s\n' % self.name )

	def checkIntf(self,intf):
      	    	"Make sure interface does not already exist before creating"
	    	if ( ' %s:' % intf ) in quietRun( 'ip link show' ):
	        	error( 'Error:', intf, 'already exists!\n' )
	        	exit( 1 )

	def createLink(self,nodeIntf):
		"Generate a local interface name, then create a link (veth interface pair) between passed remote intf name and generated local intf name"
		global localInterfaces
	        global remoteInterfaces
		localCandidIntfName = self.name +"-eth"+str(self.localIfIndex)
		self.checkIntf(localCandidIntfName)
		quietRun('ip link add ' + localCandidIntfName + ' type veth peer name '  + str(nodeIntf))
		quietRun('ip link set ' + localCandidIntfName + ' up')
		quietRun('ip link set ' + str(nodeIntf) + ' up')
		self.localIfIndex += 1 
        	info( '*** Connecting NFV Middlebox %s to SDN node %s\n' % (self.name, nodeIntf.rsplit('-', 1)[0]))
        	info( '(%s <-> %s)\n' % (localCandidIntfName, nodeIntf) )
		localInterfaces.append(localCandidIntfName)
		return

	def connectTo(self,Node):
		"Fetch next available port number on destination node and generate a remote interface name"
		remoteCandidIntfName = Node.name +"-eth" + str(Node.newPort())
		"Pass the remote intf name to generate a link"
		self.createLink(remoteCandidIntfName)
		"Connect the other end of the created link to the passed mininet node"
		_intf = Intf( remoteCandidIntfName, node=Node )
		return

	def stop(self):
		"Gracefully remove links"
		global localInterfaces
		info( '*** Stopping NFV Middlebox: %s\n' % self.name )
		for i in range(0,self.localIfIndex):   
			quietRun('ip link delete ' + localInterfaces[i])

