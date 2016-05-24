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
        ds1 = self.addHost( 'h5', ip="100.0.0.20/24" )
        ds2 = self.addHost( 'h6' , ip="100.0.0.21/24")
        ds3 = self.addHost( 'h7' , ip="100.0.0.22/24")
        ws1 = self.addHost( 'h8' , ip="100.0.0.40/24")
        ws2 = self.addHost( 'h9' , ip="100.0.0.41/24")
        ws3 = self.addHost( 'h10' , ip="100.0.0.42/24")
        insp = self.addHost( 'h11', ip="100.0.0.30/24" )


        sw1 = self.addSwitch( 's1', dpid="0000000000000201" )
        sw2 = self.addSwitch( 's2', dpid="0000000000000202" )
        sw3 = self.addSwitch( 's3', dpid="0000000000000203" )
        sw4 = self.addSwitch( 's4', dpid="0000000000000204" )
        sw5 = self.addSwitch( 's5', dpid="0000000000000205" )
        fw1 = self.addSwitch( 's6', dpid="0000000000000206" )
        fw2 = self.addSwitch( 's7', dpid="0000000000000207" )
        lb1 = self.addSwitch( 's8', dpid="0000000000000208" )
        lb2 = self.addSwitch( 's9', dpid="0000000000000209" )
        ids = self.addSwitch( 's10', dpid="0000000000000210" )
        napt = self.addSwitch( 's11', dpid="0000000000000211" )

        # Add links
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )
        self.addLink( sw1, fw1 )
        self.addLink( fw1, sw2 )
        self.addLink( ds1, sw3 )
        self.addLink( ds2, sw3 )
        self.addLink( ds3, sw3 )
        self.addLink( sw3, lb1 )
        self.addLink( lb1, sw2 )
        self.addLink( sw2, ids )
        self.addLink( ids, lb2 )
        self.addLink( lb2, sw4 )
        self.addLink( ws1, sw4 )
        self.addLink( ws2, sw4 )
        self.addLink( ws3, sw4 )
        self.addLink( insp, ids )
        self.addLink( sw2, fw2 )
        self.addLink( fw2, napt )
        self.addLink( napt, sw5 )
        self.addLink( h3, sw5 )
        self.addLink( h4, sw5 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
