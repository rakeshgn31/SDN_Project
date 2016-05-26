
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/tcp.h>
#include <click/error.hh>
#include <click/args.hh>
#include "httprequestinspector.hh"
CLICK_DECLS

HTTPRequestInspector::HTTPRequestInspector(){}
HTTPRequestInspector::~HTTPRequestInspector(){}

int HTTPRequestInspector::tcpPayloadLen( const Packet *p )
{
  //This function is inherited from HttpResponder.cc by Marcel Poisot
  //TCP payloadLen = packetLen - TCP header offset - TCP header size
  int payloadLen =  p->length() -  p->transport_header_offset() - (p->tcp_header()->th_off * 4 );
  return payloadLen;
}

//Int i=0 parse methods, Int 1 parse URIs
void HTTPRequestInspector::inputParser(int location, String input){
  int curPos=0;
  int endofword;
  Vector<String> * vectorPointer;
  if (location==0)
   vectorPointer = &Methods;
  else
   vectorPointer = &URIs;


 while ((input.find_left('-',curPos)) > 0) {
   
   endofword = input.find_left('-',curPos);
   vectorPointer->push_back(input.substring(curPos, endofword-curPos).lower());
   curPos=endofword+1;
  }

}  

int HTTPRequestInspector::configure(Vector<String> &conf, ErrorHandler *errh){
  if (Args(conf, this, errh).read_p("FORBID_METHODS", _forbiddenMethods).read_p("FORBID_URIS", _forbiddenURIs).complete())
  return -1; 
	else {
	  inputParser(0,_forbiddenMethods);
	  inputParser(1,_forbiddenURIs);
	  return 0;}
}


bool HTTPRequestInspector::isHTTPRequest( const Packet *p )
{
  //Detecting HTTP request section inherited from HttpResponder.cc by Marcel Poisot
  String buff;
  int32_t payloadLen = tcpPayloadLen(p);
  if ( payloadLen == 0 )
    return false;

  const char *payload = (const char*)p->transport_header() + (p->tcp_header()->th_off * 4);
  buff = String( payload, payloadLen );

  if (strstr(buff.c_str(), "\r\n\r\n") ){
    click_chatter("-----------------------------------------------------------------------------------------");
    click_chatter("HTTP Request header found. Fetching method and URI values");
    //Find the position of the first space in the header line
    int endofword1 = buff.find_left(' ',0);
    //Anything before that space is the method, grab it
    method = buff.substring(0, endofword1).lower();
    //Find the position of the second space in the header line
    int endofword2 = buff.find_left(' ',endofword1+1);
    //Next space pos - first space pos is the second word's length.
    //Start from first space and scoop as many chars as the length of the second word
    //into the requestURI, which is our second word variable.
    requestURI = buff.substring(endofword1,endofword2-endofword1).lower();
    click_chatter("Method: %s",method.upper().c_str());
    click_chatter("Requested URI: %s",requestURI.c_str());
    return true;
   }
    return false;
}


bool HTTPRequestInspector::signatureHit(){
    int sum=0;
    this->existsMet=0;this->existsURI=0;
    bool isForbidden;
 
    for(int f=0; f<Methods.size(); ++f){
      isForbidden = (strstr(method.c_str(), Methods[f].c_str()));
      existsMet = existsMet + (int) isForbidden;
    }
    for(int f=0; f<URIs.size(); ++f){
      isForbidden = (strstr(requestURI.c_str(), URIs[f].c_str()));
      existsURI = existsURI + (int) isForbidden;
    }

    click_chatter("Forbidden Method Hitcount: %d",existsMet);
    click_chatter("Forbidden URI Hitcount: %d",existsURI);
    sum =existsMet+existsURI;
    return (sum>0);
}


void HTTPRequestInspector::send_rst(Packet *p, unsigned long seq, int outport) {
  WritablePacket *rst_pkt;
  click_ip *iphdr;
  click_tcp *tcphdr;

  //click_chatter("SENDING RST: port %d seq: %u\n", outport, seq);

  rst_pkt = WritablePacket::make(40);
  rst_pkt->set_network_header(rst_pkt->data(), 20);
  iphdr  = rst_pkt->ip_header();
  tcphdr = rst_pkt->tcp_header();

  tcphdr->th_sport = p->tcp_header()->th_dport;
  tcphdr->th_dport = p->tcp_header()->th_sport;
  tcphdr->th_seq   = htonl(seq);
  tcphdr->th_ack   = htonl(ntohl(p->tcp_header()->th_seq) + 1);
  tcphdr->th_off   = 5;
  tcphdr->th_flags  = TH_RST | TH_ACK;
  tcphdr->th_win   = ntohs(16384);
  tcphdr->th_urp   = 0;
  tcphdr->th_sum   = 0;

  memset(iphdr, '\0', 9);
  iphdr->ip_sum = 0;
  iphdr->ip_len = htons(20);
  iphdr->ip_p   = IP_PROTO_TCP;
  iphdr->ip_src = p->ip_header()->ip_dst;
  iphdr->ip_dst = p->ip_header()->ip_src;

  //set tcp checksum
  tcphdr->th_sum = click_in_cksum((unsigned char *)iphdr, 40);
  iphdr->ip_len = htons(40);

  iphdr->ip_v   = 4;
  iphdr->ip_hl  = 5;
  iphdr->ip_id  = htons(0x1234);
  iphdr->ip_off = 0;
  iphdr->ip_ttl = 32;
  iphdr->ip_sum = 0;

  // set ip checksum
  iphdr->ip_sum = click_in_cksum(rst_pkt->data(), 20);

  output(outport).push(rst_pkt);
  return;
}


void HTTPRequestInspector::push(int, Packet *p) {

        if(!isHTTPRequest(p))
        output(0).push(p);
	else
	if(signatureHit()){
        click_chatter("Action: Drop");
        click_chatter("-----------------------------------------------------------------------------------------");
        click_chatter("\n");
        output(1).push(p);
	send_rst(p,1,2);
	}
        else { 
        click_chatter("Action: Pass");
        click_chatter("-----------------------------------------------------------------------------------------");
        click_chatter("\n");
        output(0).push(p);
	     }
        
}


CLICK_ENDDECLS
EXPORT_ELEMENT(HTTPRequestInspector)
