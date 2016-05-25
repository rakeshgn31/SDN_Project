// This file is for NAPT - ADDRESS and PORT Translator
//------------------------------------------------------------

// Average Counter and Counter elements to track the packet rate and count
//--------------------------------------------------------------------------
INT_IN_PKT_ACTR, INT_OUT_PKT_ACTR, EXT_IN_PKT_ACTR, EXT_OUT_PKT_ACTR :: AverageCounter;
INT_ARP_REQ_CTR, EXT_ARP_REQ_CTR, INT_ARP_RESP_CTR, EXT_ARP_RESP_CTR :: Counter;
INT_ICMP_PKT_CTR1, EXT_ICMP_PKT_CTR1, INT_ICMP_PKT_CTR2, EXT_ICMP_PKT_CTR2 :: Counter;
INT_SERV_PKT_CTR, EXT_SERV_PKT_CTR :: Counter;
INT_DROP_CTR, EXT_DROP_CTR :: Counter;

// External interface - Inbound and Outbound
//------------------------------------------------------------
EXT_IN	::  FromDevice(NAPT-eth0, METHOD LINUX);
EXT_OUT	::  Queue(200) -> EXT_OUT_PKT_ACTR -> ToDevice(NAPT-eth0);

// Internal interface - Inbound and Outbound
//------------------------------------------------------------
INT_IN  ::  FromDevice(NAPT-eth1, METHOD LINUX);
INT_OUT ::  Queue(200) -> INT_OUT_PKT_ACTR -> ToDevice(NAPT-eth1);

// Address Info container elements for the Interfaces
//------------------------------------------------------------
AddressInfo(INT_ADD 10.0.0.1 00:00:45:8C:72:9E);
AddressInfo(EXT_ADD 100.0.0.1 00:00:45:5C:82:1A);

// Arp Querier and Responder elements for External & Internal interfaces
//------------------------------------------------------------------------
AQ_INT  ::   ARPQuerier(INT_ADD) -> INT_OUT;
AQ_EXT  ::   ARPQuerier(EXT_ADD) -> EXT_OUT;

AR_INT  ::   ARPResponder(INT_ADD) -> INT_OUT;
AR_EXT  ::   ARPResponder(EXT_ADD) -> EXT_OUT;

// Incoming packet classifiers for both the Internal and External interfaces
//--------------------------------------------------------------------------
INT_FRAME_CLS  :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
EXT_FRAME_CLS  :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

// IP packet classifiers for Internal and External interfaces
//--------------------------------------------------------------------------
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
INT_IN  
	-> INT_IN_PKT_ACTR
	-> INT_FRAME_CLS
	-> INT_ARP_REQ_CTR
	-> AR_INT;

	INT_FRAME_CLS[1]
		-> INT_ARP_RESP_CTR
		-> [1]AQ_INT;

	INT_FRAME_CLS[2]
		-> Strip(14)
		-> CheckIPHeader
		-> INT_PKT_CLS
				-> INT_ICMP_PKT_CTR1
				-> ICMPPingResponder
				-> AQ_INT;

		   INT_PKT_CLS[1]
				-> INT_ICMP_PKT_CTR2
				-> PING_RW
				-> RIB;

		   INT_PKT_CLS[2]
				-> INT_SERV_PKT_CTR
				-> IP_RW
				-> RIB;

	INT_FRAME_CLS[3]
		-> INT_DROP_CTR
		-> Discard;

//----------Internal to External Processing--------------------

EXT_IN
	-> EXT_IN_PKT_ACTR
	-> EXT_FRAME_CLS
	-> EXT_ARP_REQ_CTR
	-> AR_EXT;

	EXT_FRAME_CLS[1]
		-> EXT_ARP_RESP_CTR
		-> [1]AQ_EXT;

	EXT_FRAME_CLS[2]
		-> Strip(14)
		-> CheckIPHeader
		-> EXT_PKT_CLS
			-> EXT_ICMP_PKT_CTR1
			-> ICMPPingResponder
			-> AQ_EXT;

		EXT_PKT_CLS[1]
			-> EXT_ICMP_PKT_CTR2
			-> [1] PING_RW [1]
			-> RIB;

		EXT_PKT_CLS[2]
			-> EXT_SERV_PKT_CTR
			-> [1] IP_RW [1]
			-> RIB;

	EXT_FRAME_CLS[3]
		-> EXT_DROP_CTR
		-> Discard;

//-----------------------Reporting------------------------------------
DriverManager(pause, wait 2s,
	print "\n\r NAPT 1 Logs dumped at /tmp/NAPT_Report.log :",
	save "=========================NAPT REPORT========================
============External INTERFACE======================
Input Packet Rate (pps)	:	$(EXT_IN_PKT_ACTR.rate)
Output Packet Rate (pps):	$(EXT_OUT_PKT_ACTR.rate)

Total # of ARP requests	:	$(EXT_ARP_REQ_CTR.count)
Total # of ARP responses:	$(EXT_ARP_RESP_CTR.count)
Total # of UDP packets	:	$(EXT_SERV_PKT_CTR.count)
Total # of ICMP packets	:	$(add($(EXT_ICMP_PKT_CTR1.count) $(EXT_ICMP_PKT_CTR2.count)))

Total # of dropped packets:	$(EXT_DROP_CTR.count)

============Internal INTERFACE======================
Input Packet Rate (pps)	:	$(INT_IN_PKT_ACTR.rate)        	   
Output Packet Rate (pps):	$(INT_OUT_PKT_ACTR.rate)
     	   		   
Total # of ARP requests	:	$(INT_ARP_REQ_CTR.count)  		   
Total # of ARP responses:	$(INT_ARP_RESP_CTR.count) 		   
Total # of UDP packets	:	$(INT_SERV_PKT_CTR.count)  		       
Total # of ICMP packets	:	$(add($(INT_ICMP_PKT_CTR1.count) $(INT_ICMP_PKT_CTR2.count)))
  		       
Total # of dropped packets:	$(INT_DROP_CTR.count)  		       
============================================================
	" /tmp/LB1_Report.log,
	stop);
