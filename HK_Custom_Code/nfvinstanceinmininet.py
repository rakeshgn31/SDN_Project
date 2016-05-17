'''
Created on May 7, 2016

@author: Huseyin Kayahan
'''
import re
import sys
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.link import Intf
from mininet.util import quietRun
from mininet.node import RemoteController
from mininet.node import (Node, Host, OVSKernelSwitch)
from nfv import NFVMiddlebox


class NetworkTopo( Topo ):
    "A simple topology of a router with three subnets (one host in each)."

    def build( self, **_opts ):
        
        h1 = self.addHost( 'h1', ip='192.168.1.100/24')
        h2 = self.addHost( 'h2', ip='192.168.1.101/24')
        sw1 = self.addSwitch( 's1' )
        sw2 = self.addSwitch( 's2' )
        
        self.addLink( h1, sw1 )
        self.addLink( h2, sw2 )
	      

def run():
    IDS = NFVMiddlebox("IDS")
    topo = NetworkTopo()
    net = Mininet( topo=topo, controller= lambda name: RemoteController( name, defaultIP='127.0.0.1' ),listenPort=6633, )  # POX
    switch1 = net.switches[ 0 ]
    switch2 = net.switches[ 1 ]
    IDS.connectTo(switch1)
    IDS.connectTo(switch2)
    

    net.start()
    CLI( net )
    net.stop()
    IDS.stop()
	
if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

