// This file is for Load Balancer 2

AddressInfo(lb2_ext_intf 100.0.0.45 100.0.0.45/24 00:00:A5:83:2D:75);
AddressInfo(lb2_inter_intf 100.0.0.45 100.0.0.45/24 00:00:89:76:3E:1C);

// Devices to read the packets
in_ext_dev :: FromDevice(LB2-eth0)
in_int_dev :: FromDevice(LB2-eth1)

// Devices to direct the output
out_ext_dev :: Queue(200) -> ToDevice(LB2-eth0)
out_int_dev :: Queue(200) -> ToDevice(LB2-eth1)

// Declare the required packet classifiers
pkt_cls_int, pkt_cls_ext :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
ip_proto_cls_ext :: IPClassifier(dst tcp port 80, icmp, -);
ip_proto_cls_int :: IPClassifier(tcp, icmp, -);
ip_pkt_cls_ext1, ip_pkt_cls_ext2 :: IPClassifier(dst host 100.0.0.45, -);


// Declare the required ARP elements
arp_resp_ext :: ARPResponder(lb2_ext_intf);
arp_resp_int :: ARPResponder(lb2_inter_intf);
arp_quer_ext :: ARPQuerier(lb2_ext_intf);
arp_quer_int :: ARPQuerier(lb2_inter_intf);
arp_quer_ext[0] -> out_ext_dev;
arp_quer_int[0] -> out_int_dev;

// Read the packets and classify them
in_ext_dev -> [0]pkt_cls_ext;
in_int_dev -> [0]pkt_cls_int;

// Handle the classified ARP Requests' Packets
pkt_cls_ext[0] -> arp_resp_ext -> Print("Ext ARP Resp - ") -> out_ext_dev;
pkt_cls_int[0] -> arp_resp_int -> Print("Int ARP Resp - ") -> out_int_dev;

// Handle the classified ARP Replies packets
pkt_cls_ext[1] -> [1]arp_quer_ext;
pkt_cls_int[1] -> [1]arp_quer_int;

// Handle the classified IP Packets for external interface
pkt_cls_ext[2]
                -> Strip(14)
                -> CheckIPHeader
                -> [0]ip_proto_cls_ext;

// Handle the TCP packets
httpServMapper::RoundRobinIPMapper(- - 100.0.0.40 - 0 1, - - 100.0.0.41 - 0 1, - - 100.0.0.42 - 0 1);
ip_rwriter::IPRewriter(httpServMapper,pattern 100.0.0.45 2000-60000 - - 1 0);
ip_proto_cls_ext[0] -> [0]ip_pkt_cls_ext1;
ip_pkt_cls_ext1[0]  -> [0]ip_rwriter;
ip_rwriter[0]
        -> IPPrint("TCP pkt to HTTP Server : ")
        -> arp_quer_int;

// Handle the ICMP packets
ip_proto_cls_ext[1] -> [0]ip_pkt_cls_ext2;
ip_pkt_cls_ext2[0]
                  -> IPPrint("ICMP destined to VIP from EXT : ")
                  -> ICMPPingResponder
                  -> arp_quer_ext;
ip_pkt_cls_ext2[1] -> ICMPError(100.0.0.45, unreachable, host)
                  -> arp_quer_ext;

// Handle the classified IP Packets for internal interface
pkt_cls_int[2]
        -> Strip(14)
        -> CheckIPHeader
        -> [0]ip_proto_cls_int;

// Handle the UDP reply packets
ip_proto_cls_int[0] -> [1]ip_rwriter;
ip_rwriter[1]
        -> IPPrint("Resp. from HTTP Server : ")
        -> arp_quer_ext;

// Handle the ICMP Packets
ip_proto_cls_int[1]
                -> IPPrint("ICMP destined to VIP from INT : ")
                -> ICMPPingResponder
                -> arp_quer_int;

// Discard all other packets
pkt_cls_ext[3]      -> Discard;
pkt_cls_int[3]      -> Discard;
ip_proto_cls_ext[2] -> Discard;
ip_proto_cls_int[2] -> Discard;
ip_pkt_cls_ext1[1]   -> Discard;
