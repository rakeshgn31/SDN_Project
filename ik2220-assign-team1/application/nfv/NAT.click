AddressInfo(NAT-in     10.0.0.1     10.0.0.0/24       00:00:C0:AE:71:EF);
AddressInfo(NAT-ex     100.0.0.1                      00:00:C0:AE:67:EF);
AddressInfo(gw-addr    100.0.0.1                      00:00:C0:AE:67:EF);


inext      :: FromDevice(NAT-eth0);
inint      :: FromDevice(NAT-eth1);
aoutext    :: ARPQuerier(100.0.0.1, 00:00:C0:AE:67:EF);
aoutint    :: ARPQuerier(10.0.0.1, 00:00:C0:AE:71:EF);
outext     :: Queue(200) -> ToDevice(NAT-eth0);
outint     :: Queue(200) -> ToDevice(NAT-eth1);
tol        :: Discard;

IPctr, 		:: AverageCounter;


rt :: StaticIPLookup(100.0.0.0/24 0,
		    100.0.0.255/32 0,
		    100.0.0.1/32 0,
		    );
 
rt[0]-> aoutext[0] -> outext;
aoutint[0] -> outint;																															

//Classify all the packets  
cint::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
cext::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
ip_proto_cls   :: IPClassifier(tcp, icmp,udp, -);
ip_pkt_cls_int :: IPClassifier(dst host 10.0.0.1, -);
ip_pkt_cls_ext :: IPClassifier(dst host 100.0.0.1, -);


//ARP decelrations

  ext_arp::ARPResponder(NAT-ex);
  int_arp::ARPResponder(NAT-in);

//Eternal arp mechanism
  inext->[0]cext;
  cext[0] -> ext_arp -> Print("ARP Resp") -> outext;
  cext[1] -> [1]aoutext;
  cext[2] ->
	Strip(14) ->
	CheckIPHeader -> 
	IPClassifier(dst host 100.0.0.1 and ip proto icmp) -> 
	IPPrint("Cls Response ") -> 
	ICMPPingResponder -> 
	rt;
cext[3] -> tol;
  
//Internal arp mechanism
 inint->  [0]cint;
 cint[0]-> int_arp -> Print("ARP Resp") -> outint;
 cint[1] -> [1]aoutint;
  cint[2] ->
	Strip(14) ->
	CheckIPHeader -> 
	IPClassifier(dst host 10.0.0.1 and ip proto icmp) -> 
	IPPrint("Cls Response ") -> 
	ICMPPingResponder -> 
	aoutint;
cint[3] -> tol;


cext[2],cint[2]->
ipclass :: IPClassifier(dst host NAT-ex,
                                 dst host NAT-in,
                                 src net NAT-in);
	// Define pattern NAT
iprw :: IPRewriterPatterns(NAT 100.0.0.1 1024-65535 - -);

rw  :: IPRewriter(pattern NAT 0 1,
                 pass 1);
				 
ipclass[0] -> [1]rw;

ip_to_host :: EtherEncap(0x800, gw-addr, NAT-ex)
         -> ToHost;
	 
ip_to_extern :: GetIPAddress(16)
        -> CheckIPHeader
        -> EtherEncap(0x800, 100.0.0.1)
        -> rt;
		
ip_to_intern :: GetIPAddress(16)
           -> CheckIPHeader
           ->aoutint

rw[0] -> ip_to_extern
//est connections
rw[1] -> estconnnect::IPClassifier(dst host NAT-ex,
                                   dst net NAT-in);
								 
		estconnnect -> ip_to_intern	

		
//Not established connections
       Action::IPClassifier(icmp type echo-reply,
                                    proto icmp,-);
								 
								 Action[0] -> [0]irw;
								 Action[1] -> [0]ierw;
								 Action[2] -> Discard;

								 
// To internal interface.  Only accept from inside network.
ipclass[1] -> IPClassifier(src net NAT-in) -> ip_to_host;

//Packets from internal


ipclass[2] -> inter_class :: IPClassifier(dst net NAT-in, -);
              inter_class[0] -> ip_to_intern;
              inter_class[1] -> ip_udp_class :: IPClassifier(tcp or udp,
                                                             icmp type echo);
                                ip_udp_class[0] -> [0]rw;
								ip_udp_class[1] -> [0]irw;
								
								
// Rewriting rules for ICMP packets
irw :: ICMPPingRewriter(eth0-ex, -);
irw[0] -> ip_to_extern;
irw[1] -> icmp_me_or_intern :: IPClassifier(dst host eth0-ex, -);
          icmp_me_or_intern[0] -> ip_to_host;
          icmp_me_or_intern[1] -> ip_to_intern;
		  
// Rewriting rules for ICMP error packets
ierw :: ICMPRewriter(rw irw);
ierw[0] -> icmp_me_or_intern;
ierw[1] -> icmp_me_or_intern;

inext,inint -> classifier
        -> CheckIPHeader(14, CHECKSUM false) // don't check checksum for speed
	-> IPctr
        -> cint,cext
	-> ALLOWctr
        -> outext,outint;

++++++++++++++++++++++++++++++++++++++
Pending work
toLoggerout  :: Queue(200)  -> ToDevice(NAT-eth0);
toLoggerin   ::Queue(200) -> ToDevice(NAT-eth1)
inext  -> DROPctr -> toLoggerout;
inint  -> DROPctr -> toLoggerin;
DriverManager(pause, wait 2s,
	print "\n\r NAT Logs dumped at /tmp/NAT.log :",
	save "=====================NAT Report=====================
Input Packet Rate (pps): $(IPctr.rate)
Output Packet Rate (pps): $(IPctr.rate)
-----------------INBOUND-------------------- 
Total#of inputpackets:
Total#of outputpackets:
Total#of ARP requests:
Total#of ARPresponses:
Total#ofservicepackets:
Total#of ICMPpackets:
Total#ofdroppedpackets:$(DROPctr.count)	  
--------------------------------------------
====================================================
	" /tmp/NAT.log,
	stop)
