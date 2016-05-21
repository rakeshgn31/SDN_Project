// This file is for Load Balancer 1

AddressInfo(lb1_ext_intf 100.0.0.25 100.0.0.25/24 00:00:45:8C:72:9E);
AddressInfo(lb1_inter_intf 100.0.0.25 100.0.0.25/24 00:00:12:56:9D:8A);

// Devices to read the packets
in_ext_dev :: FromDevice(LB1-eth0)
in_int_dev :: FromDevice(LB1-eth1)

// Devices to direct the output
out_ext_dev :: Queue(200) -> ToDevice(LB1-eth0)
out_int_dev :: Queue(200) -> ToDevice(LB1-eth1)

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

// Handle the UDP packets
dnsServMapper::RoundRobinIPMapper(- - 100.0.0.20 - 0 1, - - 100.0.0.21 - 0 1, - - 100.0.0.22 - 0 1);
ip_rwriter::IPRewriter(dnsServMapper,pattern 100.0.0.25 2000-60000 - - 1 0);
ip_proto_cls_ext[0] -> [0]ip_pkt_cls_ext1;
ip_pkt_cls_ext1[0]   -> [0]ip_rwriter;
ip_rwriter[0]
        -> IPPrint("UDP pkt to DNS Server : ")
        -> arp_quer_int;

// Handle the ICMP packets
ip_proto_cls_ext[1] -> [0]ip_pkt_cls_ext2;
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
ip_proto_cls_int[0] -> [1]ip_rwriter;
ip_rwriter[1]
        -> IPPrint("Resp. from DNS : ")
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
