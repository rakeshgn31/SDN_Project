// This file is for Load Balancer 1

AddressInfo(lb1_vip_intf 100.0.0.25 100.0.0.25/24 00:00:45:8C:72:9E);

// Devices to read the packets
in_dev1 :: FromDevice(LB1-eth0)
in_dev2 :: FromDevice(LB1-eth1)

// Devices to direct the output
out_dev1 :: Queue(100) -> ToDevice(LB1-eth0)
out_dev2 :: Queue(100) -> ToDevice(LB1-eth1)

// Declare the required packet classifiers
pkt_cls_server, pkt_cls_host :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
ip_pkt_cls1, ip_pkt_cls2 :: IPClassifier(tcp, udp, icmp, -);

// Read the packets and classify them
in_dev1 -> [0]pkt_cls_host;
in_dev2 -> [0]pkt_cls_server;

// Handle the classified ARP Requests Packets
arp_resp0, arp_resp1 :: ARPResponder(lb1_vip_intf);
pkt_cls_host[0]   -> arp_resp0 -> out_dev1;
pkt_cls_server[0] -> arp_resp1 -> out_dev2;

// Handle the classified ARP Replies packets - TODO
arp_quer1, arp_quer2::ARPQuerier(lb1_vip_intf);
pkt_cls_host[1]   -> [1]arp_quer1;
pkt_cls_server[1] -> [1]arp_quer2;

// Handle the classified IP Packets - TODO
pkt_cls_host[2] -> cip1::CheckIPHeader(14) -> [0]ip_pkt_cls1;
ip_pkt_cls1[0] -> 
ip_pkt_cls1[1] ->
ip_pkt_cls1[2] ->

pkt_cls_server[2] -> cip2::CheckIPHeader(14) -> [0]ip_pkt_cls2;
ip_pkt_cls2[0] ->
ip_pkt_cls2[1] ->
ip_pkt_cls2[2] ->

// Discard the other packets
ip_pkt_cls[3] 	  -> Discard;
pkt_cls_server[3] -> Discard;
pkt_cls_host[3]   -> Discard;