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
from mininet.link import TCLink
from nfv import NFVMiddlebox
from topotester import Tester

class NetworkTopo( Topo ):
    "A simple topology of a router with three subnets (one host in each)."

    def build( self, **_opts ):

        #Public Zone
        h1 = self.addHost( 'h1', ip='100.0.0.10/24')
        h2 = self.addHost( 'h2', ip='100.0.0.11/24')
        sw1 = self.addSwitch( 'sw1', dpid="0000000000000201" )
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )
        
        #DMZ West
        ds1 = self.addHost( 'ds1', ip='100.0.0.20/24')
        ds2 = self.addHost( 'ds2', ip='100.0.0.21/24')
        ds3 = self.addHost( 'ds3', ip='100.0.0.22/24' )
        sw3 = self.addSwitch( 'sw3', dpid="0000000000000203" )
        self.addLink( ds1, sw3 )
        self.addLink( ds2, sw3 )
        self.addLink( ds3, sw3 )
        
        #DMZ East
        ws1 = self.addHost( 'ws1', ip='100.0.0.40/24')
        ws2 = self.addHost( 'ws2', ip='100.0.0.41/24')
        ws3 = self.addHost( 'ws3', ip='100.0.0.42/24' )
        sw4 = self.addSwitch( 'sw4', dpid="0000000000000204" )
        self.addLink( ws1, sw4 )
        self.addLink( ws2, sw4 )
        self.addLink( ws3, sw4 )

        #Private Zone
        h3 = self.addHost( 'h3', ip='10.0.0.50/24', defaultGateway='10.0.0.1')
        h4 = self.addHost( 'h4', ip='10.0.0.51/24', defaultGateway='10.0.0.1')
        sw5 = self.addSwitch( 'sw5' )
        self.addLink( h3, sw5 )
        self.addLink( h4, sw5 )
        
        #Border equipment interconnect
        sw2 = self.addSwitch( 'sw2', dpid="0000000000000202" )
        fw1 = self.addSwitch( 'fw1', dpid="0000000000000205" )
        fw2 = self.addSwitch( 'fw2', dpid="0000000000000206" )
        self.addLink( sw1, fw1 )
        self.addLink( fw1, sw2 )
        self.addLink( sw2, fw2 )
        
        #Extra equip
        testsw = self.addSwitch( 'sw6', dpid="0000000000000207" )
        inspector = self.addHost( 'insp' )
        


def run():
    #dummy = NFVMiddlebox("dummy","/home/click/click/conf/dummy_bridge.click")
    IDS = NFVMiddlebox("IDS","/home/click/click/conf/alpha/IDS.click")
    NAPT = NFVMiddlebox("NAPT","/home/click/click/conf/alpha/NAPT.click")
    LB1 = NFVMiddlebox("LB1","/home/click/click/conf/alpha/LB1.click")
    LB2 = NFVMiddlebox("LB2","/home/click/click/conf/alpha/LB2.click")
    
    topo = NetworkTopo()
    net = Mininet(topo=topo, controller= lambda name: RemoteController( name, defaultIP='127.0.0.1' ),listenPort=6633, )  # POX
    sw2 = net.getNodeByName('sw2')
    sw3 = net.getNodeByName('sw3')
    sw4 = net.getNodeByName('sw4')
    sw5 = net.getNodeByName('sw5')
    fw1 = net.getNodeByName('fw1')
    fw2 = net.getNodeByName('fw2')
    testsw = net.getNodeByName('sw6')
    inspector = net.getNodeByName('insp')
    
    h3 = net.getNodeByName('h3')
    h4 = net.getNodeByName('h4')

    #Adding default gateways on hosts
    h3.cmd('route add default gw %s dev %s-eth0' % ("10.0.0.1", h3.name))
    h4.cmd('route add default gw %s dev %s-eth0' % ("10.0.0.1", h4.name))

    IDS.connectTo(sw2)
    IDS.connectTo(testsw)
    IDS.connectTo(inspector)
    
    NAPT.connectTo(fw2)
    NAPT.connectTo(sw5)
    
    LB1.connectTo(sw2)
    LB1.connectTo(sw3)
    LB2.connectTo(testsw)
    LB2.connectTo(sw4)
    
    IDS.console()
    NAPT.console()
    LB1.console()
    LB2.console()
    
    

    myTester = Tester(net)
    myTester.initServices()
    #LB2.connectTo(switch1)
    #LB2.connectTo(switch2)
    #LB2.console()
    net.start()
    myTester.NAPT()
    myTester.LB()
    myTester.IDS()

    CLI( net )
    net.stop()
    IDS.stop()
    NAPT.stop()
    LB1.stop()
    LB2.stop()
    #dummy.stop()
	
if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

