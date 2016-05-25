//EXT_IN= External interface - Inbound
EXT_IN	::  FromDevice(NAPT-eth0, METHOD LINUX);
//EXT_OUT= External interface - Outbound
EXT_OUT	::  Queue(200) -> ToDevice(NAPT-eth0);
//INT_IN= Internal interface - Inbound
INT_IN  ::  FromDevice(NAPT-eth1, METHOD LINUX);
//INT_OUT= Internal interface - Outbound
INT_OUT ::  Queue(200) -> ToDevice(NAPT-eth1);

//------------------------------------------------------------
AddressInfo(INT_ADD 10.0.0.1 00:00:45:8C:72:9E);
AddressInfo(EXT_ADD 100.0.0.1 00:00:45:5C:82:1A);

//------------------------------------------------------------
CTR_ICMP_INT, CTR_ARP_REQ_INT, CTR_ARP_RES_INT, CTR_SERV_INT, CTR_FRAME_IN_INT, CTR_FRAME_OUT_INT, CTR_DROP_INT  :: AverageCounter;
CTR_ICMP_EXT, CTR_ARP_REQ_EXT, CTR_ARP_RES_EXT, CTR_SERV_EXT, CTR_FRAME_IN_EXT, CTR_FRAME_OUT_EXT, CTR_DROP_EXT  :: AverageCounter;

//------------------------------------------------------------
// Arp Querier for Internal interface
AQ_INT  ::   ARPQuerier(INT_ADD) -> INT_OUT;
// Arp Querier for External interface
AQ_EXT  ::   ARPQuerier(EXT_ADD) -> EXT_OUT;
// Arp Responder for Internal interface
AR_INT  ::   ARPResponder(INT_ADD) -> INT_OUT;
// Arp Responder for External interface
AR_EXT  ::   ARPResponder(EXT_ADD) -> EXT_OUT;

//------------------------------------------------------------
INT_FRAME_CLS  :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
EXT_FRAME_CLS  :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

//------------------------------------------------------------
INT_PKT_CLS  :: IPClassifier(dst host 10.0.0.1 and icmp type echo, icmp type echo, -)
EXT_PKT_CLS  :: IPClassifier(dst host 100.0.0.1 and icmp type echo, icmp type echo-reply, -)

//------------------------------------------------------------

RIB  :: StaticIPLookup(10.0.0.0/24 1,
		       10.0.0.255/32 1,
		       10.0.0.1/32 1,
		       100.0.0.0/24 0,
		       100.0.0.255/32 0,
		       100.0.0.1/32 0);
RIB[1] -> AQ_INT;
RIB[0] -> AQ_EXT;	

//------------------------------------------------------------
PING_RW :: ICMPPingRewriter(pattern 100.0.0.1 - 0-65535# 0 1, drop)
IP_RW	:: IPRewriter(pattern 100.0.0.1 1024-65535# - - 0 1, drop);

//----------External to Internal Processing--------------------
INT_IN -> 
	INT_FRAME_CLS
		-> AR_INT;
	INT_FRAME_CLS[1]
		-> [1]AQ_INT;
	INT_FRAME_CLS[2]
		-> Strip(14)
		-> CheckIPHeader
		-> INT_PKT_CLS
			-> ICMPPingResponder
			-> AQ_INT;
		   INT_PKT_CLS[1]
			-> PING_RW
			-> RIB;
		   INT_PKT_CLS[2]
			-> IP_RW
			-> RIB;
	INT_FRAME_CLS[3]
		-> Discard;

//----------Internal to External Processing--------------------

EXT_IN ->
        EXT_FRAME_CLS
                -> AR_EXT; 
        EXT_FRAME_CLS[1]
                -> [1]AQ_EXT;
        EXT_FRAME_CLS[2]
		-> Strip(14)
		-> CheckIPHeader
		-> EXT_PKT_CLS
                        -> ICMPPingResponder
			-> AQ_EXT;
                   EXT_PKT_CLS[1]
                        -> [1] PING_RW [1]
			-> RIB;
		   EXT_PKT_CLS[2]
                        -> [1] IP_RW [1]
                        -> RIB;

        EXT_FRAME_CLS[3]
                -> Discard;
//-----------------------Reporting-----------------------------
DriverManager(pause, wait 2s,
	print "\n\r NAPT Logs dumped at /tmp/NAPT.log :",
	save "=========================NAPT Report========================
			      Internal INT    External INT
Input Packet Rate (pps): 	   $(CTR_FRAME_IN_INT.rate)         	   $(CTR_FRAME_IN_EXT.rate)
Output Packet Rate (pps):   	   $(CTR_FRAME_OUT_INT.rate)       	   $(CTR_FRAME_OUT_EXT.rate)

Total # of frames in:       	   $(CTR_FRAME_IN_INT.count)  		   $(CTR_FRAME_IN_EXT.count)
Total # of frames out:      	   $(CTR_FRAME_OUT_INT.count)  		   $(CTR_FRAME_OUT_EXT.count)

Total # of ARP requests:    	   $(CTR_ARP_REQ_INT.count)  		   $(CTR_ARP_REQ_EXT.count)
Total # of ARP responses:   	   $(CTR_ARP_RES_INT.count) 		   $(CTR_ARP_RES_EXT.count)

Total # of TCP&UDP packets: 	   $(CTR_SERV_INT.count)  		   $(CTR_SERV_EXT.count)
Total # of ICMP packets:   	   $(CTR_ICMP_INT.count)  		   $(CTR_ICMP_EXT.count)
Total # of dropped packets: 	   $(CTR_DROP_INT.count)  		   $(CTR_DROP_EXT.count)
============================================================
	" /tmp/NAPT.log,
	stop);
