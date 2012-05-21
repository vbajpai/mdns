/* Multicast DNS Viewer - Vaibhav Bajpai */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>

#define PORTNO 5353
#define IPV4ADDRESS "224.0.0.251"
#define IPV6ADDRESS "ff02::fb"

#define COMPRESSION_NO 0
#define COMPRESSION_YES 1

char buffer[512];

struct headerFlags{
	unsigned ra : 1;
	unsigned z : 3;
	unsigned rcode : 4;
	unsigned qr : 1;
	unsigned opcode : 4;
	unsigned aa : 1;
	unsigned tc : 1;
	unsigned rd : 1;	
}__attribute__((__packed__));
struct compressionFlags{
	unsigned flag : 2;
}__attribute__((__packed__));
struct header {
	unsigned short id;
	struct headerFlags flags;	
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} __attribute__((__packed__));
struct dnsMessage {
	struct header h;
	char nonheader[500];
} __attribute__((__packed__));
struct fixedQuestion {
	unsigned short qtype;
	unsigned short qclass;
} __attribute__((__packed__));
struct fixedResourceRecord {
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
} __attribute__((__packed__));

struct ipv4{
	unsigned byte1 : 8;
	unsigned byte2 : 8;
	unsigned byte3 : 8;
	unsigned byte4 : 8;
}ipV4;
struct ipv6{
	unsigned short group1;
	unsigned short group2;
	unsigned short group3;
	unsigned short group4;
	unsigned short group5;
	unsigned short group6;
	unsigned short group7;
	unsigned short group8;	
}ipV6;

struct dnsMessage* mydns;
struct fixedQuestion* questionSection;
struct fixedResourceRecord* resourceRecord;
struct compressionFlags* cflags;

int createIPv4Socket(){

	// create a server socket 
	int sockID;	
	if ((sockID=socket(AF_INET,SOCK_DGRAM,0)) < 0) {
		perror("socket");	
		exit(1);
	}
	
	// set processes to reuse the socket in TIMEWAIT
	u_int yes = 1;

	setsockopt(sockID,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
	#ifdef __APPLE__
		setsockopt(sockID,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof(yes));
	#endif
	
	// bind the server socket
	struct sockaddr_in serverAddress;
	bzero((char *) &serverAddress, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	serverAddress.sin_port = htons(PORTNO);
	
	if (bind(sockID, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
		perror("bind");
		exit(1);
	}		
	
	return sockID;
}

int createIPv6Socket(){
	
	// create a server socket 
	int sockID;	
	if ((sockID=socket(AF_INET6,SOCK_DGRAM,0)) < 0) {
		perror("socket");	
		exit(1);
	}
	
	// set processes to reuse the socket in TIMEWAIT
	u_int yes = 1;
	setsockopt(sockID,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
	#ifdef __APPLE__
		setsockopt(sockID,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof(yes));
	#endif
	
	// bind the server socket
	struct sockaddr_in6 serverAddress;
	bzero((char *) &serverAddress, sizeof(serverAddress));
	serverAddress.sin6_family = AF_INET6;
	serverAddress.sin6_addr = in6addr_any;
	serverAddress.sin6_port = htons(PORTNO);
	
	if (bind(sockID, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
		perror("bind");
		exit(1);
	}		
	
	return sockID;
}

void setIPv4Multicast(int sockID){

	struct ip_mreq mreq;	
	inet_pton(AF_INET, IPV4ADDRESS, &(mreq.imr_multiaddr.s_addr));	
	mreq.imr_interface.s_addr=htonl(INADDR_ANY);
	
	if (setsockopt(sockID,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0) {
		perror("setsockopt");
		exit(1);
	}		
}

void setIPv6Multicast(int sockID){
	
	struct ipv6_mreq mreq;	
	inet_pton(AF_INET6, IPV6ADDRESS, &(mreq.ipv6mr_multiaddr));		
	mreq.ipv6mr_interface=0;
	
	if (setsockopt(sockID,IPPROTO_IPV6,IPV6_JOIN_GROUP,&mreq,sizeof(mreq)) < 0) {
		perror("setsockopt");
		exit(1);
	}		
}

void receiveDatagram(int serversockID){

	bzero(buffer,512);	
	struct sockaddr_in clientAddress;	
	unsigned int clientAddressLength = sizeof(clientAddress);
	
	if (recvfrom(serversockID, buffer, sizeof(buffer), 0 , (struct sockaddr *) &clientAddress, &clientAddressLength) < 0) {
		perror("recvfrom");
		exit(1);		
	}		
}

int echoQName(char** name){
	
	while ((**name) != 0) {
		int j = 0;
		char length = **name;
		
		// check message compression
		if ((length&192) == 192){	
			
			// prepare offset
			unsigned short offset;
			memmove(&offset, *name, 2);
			offset = ntohs(offset);
			offset = offset << 2;	
			offset = offset >> 2;
			
			// recursive call echoQName()
			char* qname = buffer+offset;
			echoQName(&qname);
			return(1);
		}
		
		while (j < length){
			(*name)++; 
			printf("%c",**name);														
			j++;
		}		
		(*name)++;
		printf(".");		
	}	
	return(0);	
}

void echoDnsMessage(){
	
	// echo header section
	
		mydns = (struct dnsMessage *) buffer;
	
		printf("\n--------------");
		printf("\nHEADER SECTION");
		printf("\n--------------");
	
		// echo id
		printf("\n\nID: %u, ", ntohs(mydns->h.id));		
		
		// echo flags
		printf("QR: %u, ", mydns->h.flags.qr);
		printf("OPCODE: %u, ", mydns->h.flags.opcode);		
		printf("AA: %u, ", mydns->h.flags.aa);
		printf("TC: %u, ", mydns->h.flags.tc);
		printf("RD: %u, ", mydns->h.flags.rd);
		printf("RA: %u, ", mydns->h.flags.ra);
		printf("Z: %u, ", mydns->h.flags.z);
		printf("RCODE: %u", mydns->h.flags.rcode);
	
		// echo qdcount
		printf("\nQUERY: %u, ", ntohs(mydns->h.qdcount));
	
		// echo ancount
		printf("ANSWER: %u, ", ntohs(mydns->h.ancount));
	
		// echo nscount
		printf("AUTHORITY: %u, ", ntohs(mydns->h.nscount));
	
		// echo arcount
		printf("ADDITIONAL: %u", ntohs(mydns->h.arcount));	
	
	// echo question section
	
		printf("\n\n----------------");
		printf("\nQUESTION SECTION");
		printf("\n----------------\n");
	
		int k,l;
		char *qname = mydns->nonheader;
		for (k=1; k<=ntohs(mydns->h.qdcount); k++) {
			
			// echo name
			printf("\n");
			int flag = echoQName(&qname);
			
			// check if returned from message compression
			if(flag == 1)
				qname = qname + 2;
			else
				qname++;
			
			questionSection = (struct fixedQuestion *) qname;	
			
			// echo qclass
			switch (ntohs(questionSection->qclass)) {
				case 1:
					printf("\t\tIN");
					break;
				case 2:
					printf("\t\tCS");
					break;
				case 3:
					printf("\t\tCH");
					break;
				case 4:
					printf("\t\tHS");
					break;
				case 254:
					printf("\t\tNONE");
					break;
				case 255:
					printf("\t\tANY");
					break;
				default:
					printf("\t\tUNKNOWN");
			}
			
			// echo qtype
			switch (ntohs(questionSection->qtype)) {
				case 1:
					printf("\t\tA");
					break;
				case 2:
					printf("\t\tNS");
					break;
				case 3:
					printf("\t\tMD");
					break;
				case 4:
					printf("\t\tMF");
					break;
				case 5:
					printf("\t\tCNAME");
					break;
				case 6:
					printf("\t\tSOA");
					break;
				case 7:
					printf("\t\tMB");
					break;
				case 8:
					printf("\t\tMG");
					break;
				case 9:
					printf("\t\tMR");
					break;
				case 10:
					printf("\t\tNULL");
					break;
				case 11:
					printf("\t\tWKS");
					break;
				case 12:
					printf("\t\tPTR");
					break;
				case 13:
					printf("\t\tHINFO");
					break;
				case 14:
					printf("\t\tMINFO");
					break;
				case 15:
					printf("\t\tMX");
					break;
				case 16:
					printf("\t\tTXT");
					break;
				case 17:
					printf("\t\tRP");
					break;
				case 18:
					printf("\t\tAFSDB");
					break;
				case 24:
					printf("\t\tSIG");
					break;
				case 25:
					printf("\t\tKEY");
					break;
				case 28:
					printf("\t\tAAAA");
					break;
				case 29:
					printf("\t\tLOC");
					break;
				case 33:
					printf("\t\tSRV");
					break;
				case 35:
					printf("\t\tNAPTR");
					break;
				case 36:
					printf("\t\tKX");
					break;
				case 37:
					printf("\t\tCERT");
					break;
				case 39:
					printf("\t\tDNAME");
					break;
				case 42:
					printf("\t\tAPL");
					break;
				case 43:
					printf("\t\tDS");
					break;
				case 44:
					printf("\t\tSSHFP");
					break;
				case 45:
					printf("\t\tIPSECKEY");
					break;
				case 46:
					printf("\t\tRRSIG");
					break;
				case 47:
					printf("\t\tNSEC");
					break;
				case 48:
					printf("\t\tDNSKEY");
					break;
				case 49:
					printf("\t\tDHCID");
					break;
				case 50:
					printf("\t\tNSEC3");
					break;
				case 51:
					printf("\t\tNSEC3PARAM");
					break;
				case 55:
					printf("\t\tHIP");
					break;
				case 99:
					printf("\t\tSPF");
					break;
				case 249:
					printf("\t\tTKEY");
					break;
				case 250:
					printf("\t\tTSIG");
					break;
				case 32768:
					printf("\t\tTA");
					break;
				case 32769:
					printf("\t\tDLV");
					break;
				default:	
					printf("\t\tUNKNOWN");			
			}
			
			qname = qname + 4;
		}
	
	// echo answer | authority | additional section	
	for (l=1; l<=3; l++){
		unsigned short count;
		switch (l) {
			case 1:
				count = ntohs(mydns->h.ancount);
				printf("\n\n--------------");
				printf("\nANSWER SECTION");
				printf("\n--------------");
				break;
			case 2:
				count = ntohs(mydns->h.nscount);
				printf("\n\n-----------------");
				printf("\nAUTHORITY SECTION");
				printf("\n-----------------");
				break;
			case 3:
				count = ntohs(mydns->h.arcount);
				printf("\n\n------------------");
				printf("\nADDITIONAL SECTION");
				printf("\n------------------");
				break;
		}
		
		for (k=1; k<=count; k++) {
			
			// echo name
			printf("\n");
			
			int flag = echoQName(&qname);
			
			//check if returned from message compression
			if (flag == 1)
				qname = qname + 2;
			else
				(qname)++;
			
			resourceRecord = (struct fixedResourceRecord *) qname;
			
			// echo ttl
			printf("\t\t%d", ntohs(resourceRecord->ttl));	
			
			// echo class
			switch (ntohs(resourceRecord->class)) {
				case 1:
					printf("\t\tIN");
					break;
				case 2:
					printf("\t\tCS");
					break;
				case 3:
					printf("\t\tCH");
					break;
				case 4:
					printf("\t\tHS");
					break;
				case 254:
					printf("\t\tNONE");
					break;
				case 255:
					printf("\t\tANY");
					break;
				default:
					printf("\t\tUNKNOWN");
			}
			
			// echo type
			switch (ntohs(resourceRecord->type)) {
				case 1:
					printf("\t\tA");
					break;
				case 2:
					printf("\t\tNS");
					break;
				case 3:
					printf("\t\tMD");
					break;
				case 4:
					printf("\t\tMF");
					break;
				case 5:
					printf("\t\tCNAME");
					break;
				case 6:
					printf("\t\tSOA");
					break;
				case 7:
					printf("\t\tMB");
					break;
				case 8:
					printf("\t\tMG");
					break;
				case 9:
					printf("\t\tMR");
					break;
				case 10:
					printf("\t\tNULL");
					break;
				case 11:
					printf("\t\tWKS");
					break;
				case 12:
					printf("\t\tPTR");
					break;
				case 13:
					printf("\t\tHINFO");
					break;
				case 14:
					printf("\t\tMINFO");
					break;
				case 15:
					printf("\t\tMX");
					break;
				case 16:
					printf("\t\tTXT");
					break;
				case 17:
					printf("\t\tRP");
					break;
				case 18:
					printf("\t\tAFSDB");
					break;
				case 24:
					printf("\t\tSIG");
					break;
				case 25:
					printf("\t\tKEY");
					break;
				case 28:
					printf("\t\tAAAA");
					break;
				case 29:
					printf("\t\tLOC");
					break;
				case 33:
					printf("\t\tSRV");
					break;
				case 35:
					printf("\t\tNAPTR");
					break;
				case 36:
					printf("\t\tKX");
					break;
				case 37:
					printf("\t\tCERT");
					break;
				case 39:
					printf("\t\tDNAME");
					break;
				case 42:
					printf("\t\tAPL");
					break;
				case 43:
					printf("\t\tDS");
					break;
				case 44:
					printf("\t\tSSHFP");
					break;
				case 45:
					printf("\t\tIPSECKEY");
					break;
				case 46:
					printf("\t\tRRSIG");
					break;
				case 47:
					printf("\t\tNSEC");
					break;
				case 48:
					printf("\t\tDNSKEY");
					break;
				case 49:
					printf("\t\tDHCID");
					break;
				case 50:
					printf("\t\tNSEC3");
					break;
				case 51:
					printf("\t\tNSEC3PARAM");
					break;
				case 55:
					printf("\t\tHIP");
					break;
				case 99:
					printf("\t\tSPF");
					break;
				case 249:
					printf("\t\tTKEY");
					break;
				case 250:
					printf("\t\tTSIG");
					break;
				case 32768:
					printf("\t\tTA");
					break;
				case 32769:
					printf("\t\tDLV");
					break;
				default:	
					printf("\t\tUNKNOWN");			
			}
			
			// echo rdlength
			printf("\t\t%u", ntohs(resourceRecord->rdlength));	
			
			qname = qname + 10;
			
			// echo rdata
			
			char text[resourceRecord->rdlength];
			char* ptr;
			switch (ntohs(resourceRecord->type)) {				

				case 1:						
					memmove(&ipV4, qname, sizeof(ipV4));
					printf("\t\t%u.%u.%u.%u", ipV4.byte1, ipV4.byte2, ipV4.byte3, ipV4.byte4);
					break;
				case 28:
					memmove(&ipV6, qname, sizeof(ipV6));
					printf("\t\t%x:%x:%x:%x:%x:%x:%x:%x", ipV6.group1,ipV6.group2,ipV6.group3,ipV6.group4,ipV6.group5,ipV6.group6,ipV6.group7,ipV6.group8);
					break;
				case 16:
					strncpy(text, qname, sizeof(text));
					printf("\t\t%s", text);
 				    break;
				case 12:
					ptr = qname;
					printf("\t\t");
					echoQName(&ptr);
 				    break;
				default:
					printf("\t\tUNKNOWN");
			}
			
			
			qname = qname + ntohs(resourceRecord->rdlength);
		}
		
		printf("\n\n");
	}
}

int main(int argc, char *argv[]){
	
	int ipv4SockID = createIPv4Socket();
	
	int ipv6SockID = createIPv6Socket();
	
	setIPv4Multicast(ipv4SockID);
	
	setIPv6Multicast(ipv6SockID);
	
	fd_set fileDescriptor;
	
	/* flush fileDescriptor */
	FD_ZERO(&fileDescriptor);
	
	/* specify list of sockets */
	FD_SET(ipv4SockID, &fileDescriptor);
	FD_SET(ipv6SockID, &fileDescriptor);
	
	/* wait for incoming activity */
	select(ipv6SockID + 1, &fileDescriptor, NULL, NULL, NULL);
	
	/* switch sockets */
	if (FD_ISSET(ipv4SockID,&fileDescriptor))
		receiveDatagram(ipv4SockID);	
	
	if (FD_ISSET(ipv6SockID,&fileDescriptor))
		receiveDatagram(ipv6SockID);	
	
	echoDnsMessage();
	
	close(ipv4SockID);
	close(ipv6SockID);
	
	return 0;
}
