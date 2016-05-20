# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class Firewall (object):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent, DP):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}
    #Firewall_1
    if DP ==  '6':
      self.traffic_allowed_map = [('100.0.0.10','*','100.0.0.25','53'),('100.0.0.25','53','100.0.0.10','*'),
      ('100.0.0.11','*','100.0.0.45','80'),('100.0.0.45','80','100.0.0.11','*'),('100.0.0.11','*','100.0.0.25','53'),
      ('100.0.0.25','53','100.0.0.11','*'),('100.0.0.10','*','100.0.0.45','80'),('100.0.0.45','80','100.0.0.10','*'),
      ('100.0.0.1','*','100.0.0.10','*'),('100.0.0.1','*','100.0.0.11','*')]
    #SOUTH FIREWALL ('100.0.0.10','*','100.0.0.50','*'),('100.0.0.50','*','100.0.0.10','*'),('100.0.0.11','*','100.0.0.50','*'),('100.0.0.50','*','100.0.0.11','*'),('100.0.0.10','*','100.0.0.51','*'),('100.0.0.51','*','100.0.0.10','*'),('100.0.0.11','*','100.0.0.51','*'),('100.0.0.51','*','100.0.0.11','*')
    #IPSRC,SRCPORT,IPDST,DSTPORT,ACK - icmp request and tcp ack=0
    elif DP ==  '7':
      self.traffic_allowed_map2 = [('100.0.0.1','*','100.0.0.25','53'),('100.0.0.1','*','100.0.0.45','80'),
      ('100.0.0.1','*','100.0.0.10','*'),('100.0.0.1','*','100.0.0.11','*')]
      #self.traffic_allowed_map2 = [('100.0.0.50','*','100.0.0.50','*',0),('100.0.0.11','*','100.0.0.51','*',0),('100.0.0.11','*','100.0.0.50','*',0),('100.0.0.10','*','100.0.0.51','*',0)]
    
    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

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
    
    def checkPolicyF1(event):
      log.debug("in check policy F1")
      packet=event.parsed
      ip_src = ''
      ip_dst = ''
      src_port = ''
      dst_port = ''
      if packet.find('arp') is not None:
        return True
      icmp = packet.find('icmp')
      if icmp is not None:
        log.debug("Found IP4 Pakcet")
        ip = packet.find(pkt.ipv4)
        ip_src=ip.srcip
        ip_dst=ip.dstip
        log.debug("IP Source: %s" % ip_src)
        log.debug("IP Dest: %s" % ip_dst)
        if (icmp.type == 0):
         log.debug("ECHO REPLY")
         return True
        if icmp.type == 8:
            log.debug("ECHO REQUEST")
            for (IPS,SPort,IPD,DPort) in self.traffic_allowed_map:   
              if (ip_src==IPAddr(IPS))  and (ip_dst==IPAddr(IPD)) :
                log.debug("IN F1 Checking MAP Allowed")
                return True
      if packet.find(pkt.ipv4) is not None:
        ip = packet.find(pkt.ipv4)
        ip_src=ip.srcip
        ip_dst=ip.dstip
        if packet.find('tcp') is not None:
          return True
          if packet.find('tcp').ack== 1 :
            return True
          elif packet.find('tcp').ack== 0 :
            for (IPS,SPort,IPD,DPort) in self.traffic_allowed_map:   
                if (ip_src==IPAddr(IPS))  and (ip_dst==IPAddr(IPD)) :
                  log.debug("IN F1 Checking MAP Allowed")
                  return True
      
      and ((dst_port==DPort)or(DPort=='*'))
      if packet.find('tcp') is not None:
        src_port=packet.find('tcp').srcport
        dst_port=packet.find('tcp').dstport
      elif packet.find('udp') is not None:
        src_port=packet.find('udp').srcport
        dst_port=packet.find('udp').dstport
      
      return False

    def checkPolicyF2(event):
      log.debug("in check policy F1")
      packet=event.parsed
      ip_src = ''
      ip_dst = ''
      src_port = ''
      dst_port = ''
      if packet.find('arp') is not None:
        return True
      icmp = packet.find('icmp')
      if icmp is not None:
        log.debug("Fond IP4 Pakcet")
        ip = packet.find(pkt.ipv4)
        ip_src=ip.srcip
        ip_dst=ip.dstip
        log.debug("IP Source: %s" % ip_src)
        log.debug("IP Dest: %s" % ip_dst)
        if (icmp.type == 0):
         log.debug("ECHO REPLY")
         return True
        if icmp.type == 8:
            log.debug("ECHO REQUEST")
            for (IPS,SPort,IPD,DPort) in self.traffic_allowed_map2:   
              if (ip_src==IPAddr(IPS)) :
                log.debug("IN F2 Checking MAP Allowed")
                return True
      if packet.find(pkt.ipv4) is not None:
        ip = packet.find(pkt.ipv4)
        ip_src=ip.srcip
        ip_dst=ip.dstip
        if packet.find('tcp') is not None:
          return True
          
          if packet.find('tcp').ack== 1 :
            log.debug("F2 ACK 1 found")
            return True
          elif packet.find('tcp').ack== 0 :
            log.debug("F2 ACK 0 found")
            for (IPS,SPort,IPD,DPort) in self.traffic_allowed_map2:   
                if (ip_src==IPAddr(IPS)) :
                  log.debug("IN F2 Checking MAP Allowed")
                  return True
      
      and ((dst_port==DPort)or(DPort=='*'))
      if packet.find('tcp') is not None:
        src_port=packet.find('tcp').srcport
        dst_port=packet.find('tcp').dstport
      elif packet.find('udp') is not None:
        src_port=packet.find('udp').srcport
        dst_port=packet.find('udp').dstport
      
      return False
    #Handle
    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      DP=dpid_to_str(event.dpid)
      if DP ==  '6':
        if checkPolicyF1(event) == False:
          drop()
          return
      if DP ==  '7':
        if checkPolicyF2(event) == False:
          drop()
          return
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)
