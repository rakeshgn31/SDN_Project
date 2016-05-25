#Code from http://mininet.org/blog/2013/06/03/automating-controller-startup/
from mininet.node import Controller
from os import environ

POXDIR = environ[ 'HOME' ] + '/pox'

class GR1POX( Controller ):
    def __init__( self, name, cdir=POXDIR,
                  command='python pox.py',
			  
                  cargs=( 'openflow.of_01 --port=%s '
			  'tests.controller' ),
                  **kwargs ):
        Controller.__init__( self, name, cdir=cdir,
                             command=command,
                             cargs=cargs, **kwargs )

controllers={ 'GR1POX': GR1POX }