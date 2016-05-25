// This file is for IDS Packet Detection and Inspection
//------------------------------------------------------------

// Average Counter and Counter elements to track the packet rate and count
//----------------------------------------------------------------------------
EXT_IN_PKT_ACTR, EXT_OUT_PKT_ACTR, INT_IN_PKT_ACTR, INT_OUT_PKT_ACTR :: AverageCounter;
IP_CTR, HTTP_CTR, ALLOW_CTR, DROP_CTR :: Counter;

// TO and FROM Devices for Internal and External interfaces of IDS
//------------------------------------------------------------------
toEth0   :: Queue(200) -> INT_OUT_PKT_ACTR -> ToDevice(IDS-eth0);
out      :: Queue(200) -> EXT_OUT_PKT_ACTR -> ToDevice(IDS-eth1);
toLogger :: Queue(200) -> ToDevice(IDS-eth2);

in_device :: FromDevice(IDS-eth0, METHOD LINUX);
FromDevice(IDS-eth1, METHOD LINUX) -> INT_IN_PKT_ACTR -> toEth0;

// IDS Inspection element 
//------------------------------------------------------------------
IDS :: HTTPRequestInspector("GET-HEAD-OPTIONS-TRACE-DELETE-CONNECT-","cat%20/etc/passwd-cat%20/var/log/-INSERT-UPDATE-DELETE-");

// Incoming packet classifiers and IP Packet classifier
//----------------------------------------------------------------------------
classifier      :: Classifier(12/0800, -);
ip_classifier   :: IPClassifier(dst tcp port 80 and tcp opt ack, -);

//----------------------------------------------------------------------------
in_device
	-> EXT_IN_PKT_ACTR
	-> classifier
	-> IP_CTR
    -> CheckIPHeader(14, CHECKSUM false) // don't check checksum for speed
    -> ip_classifier
	-> HTTP_CTR
    -> IDS
	-> ALLOW_CTR
    -> out;

classifier[1] -> out;
ip_classifier[1] -> out;
IDS[1] -> DROP_CTR -> toLogger;
IDS[2] -> EtherMirror -> toEth0;

//-------------------------REPORTING------------------------------------------
DriverManager(pause, wait 2s,
	print "\n\r IDS Logs dumped at /tmp/IDS.log :",
	save "=====================IDS Report=====================
============External INTERFACE======================
Input Packet Rate (pps)	: $(EXT_IN_PKT_ACTR.rate)
Output Packet Rate (pps): $(EXT_OUT_PKT_ACTR.rate)

Total # of packets		: $(IP_CTR.count)
Total # of HTTP packets	: $(HTTP_CTR.count)
      # of allowed		: $(ALLOW_CTR.count)
      # of dropped		: $(DROP_CTR.count)
	  
============Internal INTERFACE======================
Input Packet Rate (pps)	: $(INT_IN_PKT_ACTR.rate)
Output Packet Rate (pps): $(INT_OUT_PKT_ACTR.rate)
====================================================
	" /tmp/IDS.log,
	stop);
