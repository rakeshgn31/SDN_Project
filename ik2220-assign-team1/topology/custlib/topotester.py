"""
Instance of this class creates links that is available in iproute2 toolkit between a mininet node such as a switch and the kernel of the host machine/VM that
mininet runs on. While one end (virtual ethernet) of the link is connected to the mininet node, the other end is another veth generated in the kernel waiting to 
be connected to anything.

One use-case is to develop an NFV middlebox using Click modular router (CMR) and connect the other end of the link. 
Tested with userspace CMR. 
    
Author: Huseyin Kayahan
"""

#from mininet.link import Intf
#from mininet.node import (Node)
from mininet.log import setLogLevel, info, error
from mininet.util import quietRun
from mininet.net import Mininet
from mininet.node import Host
from pcapquerier import PcapQuerier
#from nfv import NFVMiddlebox
import subprocess
import dpkt
import time
import urllib
import sys
class Tester:
 	
	def __init__(self, Mininet):
		self.netInstance = Mininet
		for host in self.netInstance.hosts:
			host.cmd ('mkdir -p /tmp/%s' %host.name)
    		info("---------------------------------------------------------\n")
		info("---------WELCOME TO AUTOMATED TEST SUITE-----------------\n")
    	 	info("This suite will perform series of tests and then return to mininet> \n")
    		info("Would you like to proceed? (Y/n). Choosing n will immediately return to mininet> \n")
		answer = sys.stdin.read(1)
		print("aq")
		print (answer)
        	if answer.strip().lower() == 'n':
			self.status = False
			print("pressed no")

		else:
			print("pressed yes")
			self.status = True
		print("\n")
    
	def IDS(self):
	        if not self.status:
        	    return
		IDStester = self.netInstance.getNodeByName('h2')
		targetSrv = "100.0.0.45"
		sniffer = self.netInstance.getNodeByName('insp')
		sniffer.cmd ('rm -f /tmp/%s/idscapture.pcap' %sniffer.name)
		sniffer.cmd ('tcpdump tcp -w /tmp/%s/idscapture.pcap &' %sniffer.name)
		info("-------------------------------------------\n")
                info("Starting Test: IDS\n")
		info("Checking test dependencies\n")
		pingoput=IDStester.cmd ('ping %s -c 5'%targetSrv)
	        """
                lsofoput=targetSrv.cmd ('lsof -i tcp:80')
       		"""
		ncoput=IDStester.cmd('nc -vz %s 80'%targetSrv)
		
		try:
			assert pingoput.find('time=') != -1
		except AssertionError: 
			print("Server->Client Reachability: PING Failed")
			info("One or more test dependencies failed. Will not proceed with IDS the test.\n")
                        info("-------------------------------------------\n")
			return
		else:	
			print("Server->Client Reachability(PING): PASS")
		"""
        	try:
			assert lsofoput.find('http') != -1
		except AssertionError:
			print("HTTP Server Service: Failed")
                        info("One or more test dependencies failed. Will not proceed with the IDS test.\n")
	                info("-------------------------------------------\n")
			return
		else:
			print("HTTP Server Service: PASS")
	        """
		try:
	                assert ncoput.find('succeeded') != -1
                except AssertionError:
                        print("Client->Server Reachability: Cannot reach port 80 on target server.")
                        info("One or more test dependencies failed. Will not proceed with the IDS test.\n")
                        info("-------------------------------------------\n")
                        return
                else:
                        print("Client->Server Reachability(Netcat to TCP 80): PASS")




		info("IDS Test Dependencies are met. Proceeding with the IDS test....\n")
                info("-------------------------------------------\n")
                info("Generating HTTP traffic from test source...\n")
        
        
	        
        	
		info("Testing Method: GET\n")
		GEToput1 = IDStester.cmd ('wget --timeout=5 -t 1 -O - http://%s'%targetSrv)
		"""
	        GEToput2 = IDStester.cmd ('wget --timeout=5 -t 1 -O - "http://100.0.0.45/cat /etc/passwd"')
		GEToput3 = IDStester.cmd ('wget --timeout=5 -t 1 -O - "http://%s/cat /var/log"'%targetSrv)
		GEToput4 = IDStester.cmd ('wget --timeout=5 -t 1 -O - http://%s/INSERT'%targetSrv)
		GEToput5 = IDStester.cmd ('wget --timeout=5 -t 1 -O - http://%s/UPDATE'%targetSrv)
		GEToput6 = IDStester.cmd ('wget --timeout=5 -t 1 -O - http://%s/DELETE'%targetSrv)
		#print(GEToput1)
                #print(GEToput2)
                #print(GEToput3)
                #print(GEToput4)
                #print(GEToput5)
                #print(GEToput6)
		"""
	
		info("Testing Method: POST\n")
		POSToput1 = IDStester.cmd ('wget --post-data= --timeout=5 -t 1 http://%s'%targetSrv)
	        """
                POSToput2 = IDStester.cmd ('wget --post-data= --timeout=5 -t 1 "http://%s/cat /etc/passwd"'%targetSrv)
                POSToput3 = IDStester.cmd ('wget --post-data= --timeout=5 -t 1 "http://%s/cat /var/log"'%targetSrv)
                POSToput4 = IDStester.cmd ('wget --post-data= --timeout=5 -t 1 http://%s/INSERT'%targetSrv)
                POSToput5 = IDStester.cmd ('wget --post-data= --timeout=5 -t 1 http://%s/UPDATE'%targetSrv)
                POSToput6 = IDStester.cmd ('wget --post-data= --timeout=5 -t 1 http://%s/DELETE'%targetSrv)
       		"""        
		#print(POSToput1)
                #print(POSToput2)
                #print(POSToput3)
                #print(POSToput4)
                #print(POSToput5)
                #print(POSToput6)

                info("HTTP traffic generation completed.\n")
                info("-------------------------------------------\n")
        	info("Crosschecking generated traffic with captured offedning traffic at IDS sniffer \n")
                sniffer.cmd ('kill %tcpdump')
		IDSPcapQuerier = PcapQuerier("/tmp/%s/idscapture.pcap"%sniffer.name)
		alloweds = ['POST /','POST /legitimate']
		forbids = ['GET /', 'POST /cat%20/etc/passwd', 'GET /cat%20/var/log']
		
		try:
                        assert  IDSPcapQuerier.httpContainsMetURI(forbids) 
                except AssertionError:
                        print("IDS operation has failed: False-Negative")
                        info("-------------------------------------------\n")
                        IDSPcapQuerier.stop()
			return
		else:
			print("IDS has dropped offending traffic: PASS")
		
		try:
                        assert  not IDSPcapQuerier.httpContainsMetURI(alloweds)
                except AssertionError:
                        print("IDS operation has failed: False-Positive")
                        info("-------------------------------------------\n")
			IDSPcapQuerier.stop()
                        return
		else:
                        print("IDS has not dropped legitimate traffic: PASS")

                info("-------------------------------------------\n")
                print("IDS has successfully passed all tests!")
                info("-------------------------------------------\n")
		IDSPcapQuerier.stop()
        	

    #Port should be passed as proto:port, i.e tcp:80    
    	def isListeningOn(self, Host, port):
            result = Host.cmd ('lsof -i %s'%port)
            if result.find(':%s'%result.partition(':')[2]) == -1:
            	return False
            else:
            	return True
    
	def pingCanReach(self,srcNode,dstNode):
        	result = srcNode.cmd('ping %s -c 5'%dstNode.IP(dstNode.intf()))
        	if result and result.find('time=') != -1:
            		return True
        	else:
            		return False



        
	def initServices(self):
        	global HTTPsrvs
        	HTTPsrvs = [self.netInstance.getNodeByName('ws1'),self.netInstance.getNodeByName('ws2'),self.netInstance.getNodeByName('ws3')]
	        for server in HTTPsrvs:
                    server.cmd('python /home/click/mininet/custom/services/%s.py 80 &' %server.name)
    	    


	def NAPT(self):
	        if not self.status:
        	    return
		tester = self.netInstance.getNodeByName('h3')
                pingTarget = self.netInstance.getNodeByName('h1')
                tcpTarget = self.netInstance.getNodeByName('h2')
                udpTarget = self.netInstance.getNodeByName('h1')

		info("-------------------------------------------\n")
                info("Starting Test: NAPT\n")
		pingTarget.cmd ('rm -f /tmp/%s/naptcapture.pcap' %pingTarget.name)
                pingTarget.cmd ('tcpdump icmp[icmptype] == 8 -w /tmp/%s/icmpnaptcapture.pcap &' %pingTarget.name)
		pingoput=tester.cmd ('ping %s -c 10' %pingTarget.IP(pingTarget.intf()))
                pingTarget.cmd ('kill %tcpdump')
		
		
		try:
                        assert pingoput.find('time=') != -1
                except AssertionError:
                        print("Source->Destination Reachability: PING Failed (no response)")
                        info("-------------------------------------------\n")
                        return
                else:
                        print("Server->Client Reachability(PING): PASS")
		ICMPPcapQuerier = PcapQuerier("/tmp/%s/icmpnaptcapture.pcap" %pingTarget.name)
			
		try:
			#The string passed to SrcIP is NAPT interface IP
			assert ICMPPcapQuerier.srcIP("100.0.0.1")
		except AssertionError:
                        print("NAPT ICMP Function Failed: ICMP Source IP has not been translated.")
                        info("-------------------------------------------\n")
			ICMPPcapQuerier.stop()
                        return
		else:
			print("NAPT ICMP Function: PASS")
                        info("-------------------------------------------\n")
		ICMPPcapQuerier.stop()



                tcpTarget.cmd ('rm -f /tmp/%s/tcpnaptcapture.pcap' %tcpTarget.name)
		tcpTarget.cmd('iperf -s &')
		tcpTarget.cmd('tcpdump tcp and dst port 5001 -w /tmp/%s/tcpnaptcapture.pcap &' %tcpTarget.name)
		iperfoput = tester.cmd ('iperf -c %s -t 0.2 -l 8' %tcpTarget.IP(tcpTarget.intf()))
		#Wait a bit for iperf to complete
		time.sleep(3)
                tcpTarget.cmd ('kill %iperf')
                tcpTarget.cmd ('kill %tcpdump')
                TCPPcapQuerier = PcapQuerier("/tmp/%s/tcpnaptcapture.pcap" %tcpTarget.name)

		
		try:
                        assert iperfoput.find('KBytes') != -1
                except AssertionError:
                        print("NAPT TCP Function Failed: Data has not reached the destination.")
                        info("-------------------------------------------\n")
                	TCPPcapQuerier.stop()
		        return
                else:
                        print("NAPT TCP data transfer: PASS")
		


		try:
                        #The string passed to SrcIP is NAPT interface IP
                        assert TCPPcapQuerier.srcIP("100.0.0.1")
                except AssertionError:
                        print("NAPT TCP Function Failed: TCP Source IP has not been translated.")
                        info("-------------------------------------------\n")
                        TCPPcapQuerier.stop()
                        return
                else:
                        print("NAPT TCP source translation: PASS")
                        info("-------------------------------------------\n")

		TCPPcapQuerier.stop()
				
		udpTarget.cmd ('rm -f /tmp/%s/udpnaptcapture.pcap' %udpTarget.name)
                udpTarget.cmd('iperf -s -u &')
                udpTarget.cmd('tcpdump udp and dst port 5001 -w /tmp/%s/udpnaptcapture.pcap &' %udpTarget.name)
                iperfoput = tester.cmd ('iperf -c %s -t 0.2 -b 2M' %udpTarget.IP(udpTarget.intf()))
                #Wait a bit for iperf to complete
                time.sleep(3)
                udpTarget.cmd ('kill %iperf')
                udpTarget.cmd ('kill %tcpdump')
                UDPPcapQuerier = PcapQuerier("/tmp/%s/udpnaptcapture.pcap" %udpTarget.name)


                try:
                        assert iperfoput.find('KBytes') != -1
                except AssertionError:
                        print("NAPT UDP Function Failed: Data has not reached the destination.")
                        info("-------------------------------------------\n")
                        UDPPcapQuerier.stop()
                        return
                else:
                        print("NAPT UDP data transfer: PASS")

		try:
                        #The string passed to SrcIP is NAPT interface IP
                        assert UDPPcapQuerier.srcIP("100.0.0.1")
                except AssertionError:
                        print("NAPT UDP Function Failed: UDP Source IP has not been translated.")
                        info("-------------------------------------------\n")
                        UDPPcapQuerier.stop()
                        return
                else:
                        print("NAPT UDP source translation: PASS")
                        info("-------------------------------------------\n")
                UDPPcapQuerier.stop()

		print("NAPT has successfully passed all tests!")
                info("-------------------------------------------\n")

	def LB(self):
                if not self.status:
                    return
                fetchedContents = " "
                dnsAnswers= " "
                global HTTPsrvs
                HTTPtester = self.netInstance.getNodeByName('h3')
                HTTPsrvs = [self.netInstance.getNodeByName('ws1'),self.netInstance.getNodeByName('ws2'),self.netInstance.getNodeByName('ws3')]              
                info("-------------------------------------------\n")
                info("Starting Test: Load-Balancer\n")
                info("-------------------------------------------\n")
                
                info("Test 1: Load balancing web servers\n")
                info("Checking test dependencies\n")
		           
                for server in HTTPsrvs:
                    server.cmd('python /home/click/mininet/custom/services/%s.py 80 &' %server.name)

		
                
                pingoput=HTTPtester.cmd ('ping 100.0.0.45 -c 5')
                try:
                        assert pingoput.find('time=') != -1
                except AssertionError:
                        print("Server->Client Reachability: PING Failed (%s to LB2 interface)." %(HTTPtester.IP(HTTPtester.intf())))
                        info("One or more test dependencies failed. Will not proceed with the Load-balancer test.\n")
                        info("-------------------------------------------\n")
                        return
                print("Servers->Client Reachability(PING): PASS")
                
                
                for server in HTTPsrvs:
                    try:
                        assert self.isListeningOn(server, 'tcp:http')
                    except AssertionError:
                        print("HTTP Server Service: Failed")
                        info("One or more test dependencies failed. Will not proceed with the Load-Balancer test.\n")
                        info("-------------------------------------------\n")
                        return
                    
                print("HTTP Server Service: PASS")
                info("Load-Balancer Test 1 Dependencies are met. Proceeding with the Test 1....\n")
                info("-------------------------------------------\n")
                 
		                             
                for server in HTTPsrvs:
                    fetchedContents = fetchedContents + HTTPtester.cmd('wget --post-data= --timeout=5 -t 1 -O - http://100.0.0.45')
                
                for server in HTTPsrvs:
                    try:
                            assert fetchedContents.find('server %s'%server.name) != -1
                    except AssertionError:
                            print("Load-Balancer HTTP Function Failed: Client has not fetched content from server %s." %server.IP(server.intf()))
                            info("-------------------------------------------\n")
                            return
                    else:
                            print("Load-Balancer HTTP - Content from Webserver %s: PASS" %server.name)
                print("Load-Balancer Test 2 result: PASS")
                info("-------------------------------------------\n")
               
                
                info("Test 2: Load balancing DNS servers\n")
                info("Checking test dependencies\n")
                               
                DNStester = self.netInstance.getNodeByName('h4')
                DNSsrvs = [self.netInstance.getNodeByName('ds1'),self.netInstance.getNodeByName('ds2'),self.netInstance.getNodeByName('ds3')]
                for server in DNSsrvs:
                   server.cmd('python /home/click/mininet/custom/services/%s.py &' %server.name)
                
                pingoput=DNStester.cmd ('ping %s -c 5'%"100.0.0.25")
                try:
                        assert pingoput.find('time=') != -1
                except AssertionError:
                        print("Server->Client Reachability: PING Failed (%s to %s)." %(DNStester.IP(DNStester.intf()),"100.0.0.25"))
                        info("One or more test dependencies failed. Will not proceed with the Load-balancer test.\n")
                        info("-------------------------------------------\n")
                        return
                print("Server->Client Reachability(PING): PASS")
                         
                                
                for server in DNSsrvs:
                    try:
                        assert self.isListeningOn(server,'udp:domain')
                    except AssertionError:
                        print("DNS Server Service: Failed")
                        info("One or more test dependencies failed. Will not proceed with the Load-Balancer test.\n")
                        info("-------------------------------------------\n")
                        return
                    
                print("DNS Server Service: PASS")
                info("Load-Balancer Test 2 Dependencies are met. Proceeding with the Test 2....\n")
                info("-------------------------------------------\n")
                   
                for server in DNSsrvs:
                    dnsAnswers = dnsAnswers + DNStester.cmd('nslookup test.ik2220group1.com 100.0.0.25')
                
                for server in DNSsrvs:
                    try:
                            assert dnsAnswers.find('%s.%s.%s.%s'%(str(DNSsrvs.index(server)+1),str(DNSsrvs.index(server)+1),str(DNSsrvs.index(server)+1),str(DNSsrvs.index(server)+1))) != -1
                    except AssertionError:
                            print("Load-Balancer DNS Function Failed: Client has not fetched the answer from server %s." %server.IP(server.intf()))
                            info("-------------------------------------------\n")
                            return
                    else:
                             print("Load-Balancer DNS - Content from DNS server %s: PASS" %server.name)
                print("Load-Balancer Test 2 result: PASS")
                info("-------------------------------------------\n")
                print("Load-Balancer has successfully passed all tests!")
                info("-------------------------------------------\n")         
        	   
                
