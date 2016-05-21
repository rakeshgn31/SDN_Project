#ifndef CLICK_HTTPREQUESTINSPECTOR_HH
#define CLICK_HTTPREQUESTINSPECTOR_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS

class HTTPRequestInspector : public Element {
        public:

	        HTTPRequestInspector();
                ~HTTPRequestInspector();
                const char *class_name() const { return "HTTPRequestInspector"; }
                const char *port_count() const { return "1/1-2"; }
                const char *processing() const { return PUSH; }
                void push(int, Packet *);
                int tcpPayloadLen( const Packet *p );
                bool isHTTPRequest( const Packet *p );
		int configure(Vector<String> & , ErrorHandler *) CLICK_COLD;
		void inputParser(int, String);


        private:
                
		bool signatureHit();
        	int existsMet, existsURI;
		//One-line delimited element inputs
		String _forbiddenMethods, _forbiddenURIs;
		String method, requestURI;
		//Delimiter-free inputs for comparison
		Vector<String> Methods, URIs;

};
CLICK_ENDDECLS
#endif
