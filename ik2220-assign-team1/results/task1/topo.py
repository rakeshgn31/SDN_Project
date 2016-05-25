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
    


        sw1 = self.addSwitch( 's1', dpid="0000000000000201" )
   
        # Add links
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )
        


topos = { 'mytopo': ( lambda: MyTopo() ) }