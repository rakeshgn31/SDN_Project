from mininet.topo import Topo


class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost( 'h1' , ip="100.0.0.10/24" )
        h2 = self.addHost( 'h2' , ip="100.0.0.11/24" )
        h3 = self.addHost( 'h3' , ip="100.0.0.50/24")
        h4 = self.addHost( 'h4' , ip="100.0.0.51/24")
        


        sw1 = self.addSwitch( 's1', dpid="0000000000000201" )
        sw2 = self.addSwitch( 's2', dpid="0000000000000202" )
        fw1 = self.addSwitch( 's3', dpid="0000000000000203" )
       

        # Add links
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )
        self.addLink( sw1, fw1 )
        self.addLink( fw1, sw2 )
        self.addLink( h3, sw2 )
        self.addLink( h4, sw2 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
