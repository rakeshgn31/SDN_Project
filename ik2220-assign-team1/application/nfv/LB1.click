// This file is for Load Balancer 1

AddressInfo(lb1_ext_intf 100.0.0.25 100.0.0.25/24 00:00:45:8C:72:9E);
AddressInfo(lb1_inter_intf 100.0.0.25 100.0.0.25/24 00:00:12:56:9D:8A);

// Counters for report generation
INT_IN_PKT_ACTR, INT_OUT_PKT_ACTR, EXT_IN_PKT_ACTR, EXT_OUT_PKT_ACTR :: AverageCounter;
INT_ARP_REQ_CTR, EXT_ARP_REQ_CTR, INT_ARP_RESP_CTR, EXT_ARP_RESP_CTR :: Counter;
INT_SERV_PKT_CTR, EXT_SERV_PKT_CTR, INT_ICMP_PKT_CTR, EXT_ICMP_PKT_CTR :: Counter;
INT_DROP_CTR1, INT_DROP_CTR2, EXT_DROP_CTR1, EXT_DROP_CTR2, EXT_DROP_CTR3 :: Counter;

// Devices to read the packets
in_ext_dev :: FromDevice(LB1-eth0, SNIFFER false, METHOD LINUX)
in_int_dev :: FromDevice(LB1-eth1, SNIFFER false, METHOD LINUX)

// Devices to direct the output
out_ext_dev :: Queue(200) -> EXT_OUT_PKT_ACTR -> ToDevice(LB1-eth0)
out_int_dev :: Queue(200) -> INT_OUT_PKT_ACTR -> ToDevice(LB1-eth1)

// Declare the required packet classifiers
pkt_cls_int, pkt_cls_ext :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
ip_proto_cls_ext :: IPClassifier(dst udp port 53, icmp, -);
ip_proto_cls_int :: IPClassifier(udp, icmp, -);
ip_pkt_cls_ext1, ip_pkt_cls_ext2 :: IPClassifier(dst host 100.0.0.25, -);

// Declare the required ARP elements
arp_resp_ext :: ARPResponder(lb1_ext_intf);
arp_resp_int :: ARPResponder(lb1_inter_intf);
arp_quer_ext :: ARPQuerier(lb1_ext_intf);
arp_quer_int :: ARPQuerier(lb1_inter_intf);
arp_quer_ext[0] -> out_ext_dev;
arp_quer_int[0] -> out_int_dev;

// Round robin and IP Rewriter elements
dnsServMapper::RoundRobinIPMapper(100.0.0.25 - 100.0.0.20 - 0 1, 100.0.0.25 - 100.0.0.21 - 0 1, 100.0.0.25 - 100.0.0.22 - 0 1);
ip_rwriter::IPRewriter(dnsServMapper,pattern 100.0.0.25 2000-60000 - - 1 0);

// Read the packets and classify them
in_ext_dev -> EXT_IN_PKT_ACTR -> [0]pkt_cls_ext;
in_int_dev -> INT_IN_PKT_ACTR -> [0]pkt_cls_int;

// Handle the classified ARP Requests' Packets
pkt_cls_ext[0] -> EXT_ARP_REQ_CTR -> arp_resp_ext -> Print("Ext ARP Resp - ") -> out_ext_dev;
pkt_cls_int[0] -> INT_ARP_REQ_CTR -> arp_resp_int -> Print("Int ARP Resp - ") -> out_int_dev;

// Handle the classified ARP Replies packets
pkt_cls_ext[1] -> EXT_ARP_RESP_CTR -> [1]arp_quer_ext;
pkt_cls_int[1] -> INT_ARP_RESP_CTR -> [1]arp_quer_int;

// Handle the classified IP Packets for external interface
pkt_cls_ext[2]
                -> Strip(14)
                -> CheckIPHeader
                -> [0]ip_proto_cls_ext;

// Handle the UDP packets
ip_proto_cls_ext[0] -> EXT_SERV_PKT_CTR -> [0]ip_pkt_cls_ext1;
ip_pkt_cls_ext1[0]  -> [0]ip_rwriter;
ip_rwriter[0] -> arp_quer_int;

// Handle the ICMP packets
ip_proto_cls_ext[1] -> EXT_ICMP_PKT_CTR -> [0]ip_pkt_cls_ext2;
ip_pkt_cls_ext2[0]
                  -> IPPrint("ICMP destined to VIP from EXT : ")
                  -> ICMPPingResponder
                  -> arp_quer_ext;
ip_pkt_cls_ext2[1] -> ICMPError(100.0.0.25, unreachable, host)
                  -> arp_quer_ext;

// Handle the classified IP Packets for internal interface
pkt_cls_int[2]
        -> Strip(14)
        -> CheckIPHeader
        -> [0]ip_proto_cls_int;

// Handle the UDP reply packets
ip_proto_cls_int[0] -> INT_SERV_PKT_CTR -> [1]ip_rwriter;
ip_rwriter[1] -> Print("Resp. from DNS : ") -> arp_quer_ext;

// Handle the ICMP Packets
ip_proto_cls_int[1]
				-> INT_ICMP_PKT_CTR
                -> IPPrint("ICMP destined to VIP from INT : ")
                -> ICMPPingResponder
                -> arp_quer_int;

// Discard all other packets
pkt_cls_ext[3]      -> EXT_DROP_CTR1 -> Discard;
pkt_cls_int[3]      -> INT_DROP_CTR1 -> Discard;
ip_proto_cls_ext[2] -> EXT_DROP_CTR2 -> Discard;
ip_proto_cls_int[2] -> INT_DROP_CTR2 -> Discard;
ip_pkt_cls_ext1[1]  -> EXT_DROP_CTR3 -> Discard;

//-----------------------Reporting-----------------------------
DriverManager(pause, wait 2s,
	print "\n\r Load Balancer 1 Logs dumped at /tmp/LB1_Report.log :",
	save "=========================LB1 REPORT========================
============External INTERFACE======================
Input Packet Rate (pps)	:	$(EXT_IN_PKT_ACTR.rate)
Output Packet Rate (pps):	$(EXT_OUT_PKT_ACTR.rate)

Total # of ARP requests	:	$(EXT_ARP_REQ_CTR.count)
Total # of ARP responses:	$(EXT_ARP_RESP_CTR.count)
Total # of UDP packets	:	$(EXT_SERV_PKT_CTR.count)
Total # of ICMP packets	:	$(EXT_ICMP_PKT_CTR.count)

Total # of dropped packets:	$(add( $(EXT_DROP_CTR1.count) $(EXT_DROP_CTR2.count) $(EXT_DROP_CTR3.count)))

============Internal INTERFACE======================
Input Packet Rate (pps)	:	$(INT_IN_PKT_ACTR.rate)        	   
Output Packet Rate (pps):	$(INT_OUT_PKT_ACTR.rate)
     	   		   
Total # of ARP requests	:	$(INT_ARP_REQ_CTR.count)  		   
Total # of ARP responses:	$(INT_ARP_RESP_CTR.count) 		   
Total # of UDP packets	:	$(INT_SERV_PKT_CTR.count)  		       
Total # of ICMP packets	:	$(INT_ICMP_PKT_CTR.count)
  		       
Total # of dropped packets:	$(add( $(INT_DROP_CTR1.count) $(INT_DROP_CTR2.count)))
============================================================
	" /tmp/LB1_Report.log,
	stop);