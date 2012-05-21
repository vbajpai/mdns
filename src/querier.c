/* Multicast DNS Querier - Vaibhav Bajpai */

#define _GNU_SOURCE

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<time.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SEND 0
#define RECEIVE 1 
#define PRINT_YES 1
#define PRINT_NO 0

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
}__attribute__((__packed__)); 
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

char buffer[512];
struct dnsMessage dns;
struct dnsMessage *mydns;
struct fixedQuestion question;
struct fixedQuestion* questionSection;
struct fixedResourceRecord* resourceRecord;

int createIPv4Socket(int flag, char*ipv4address, char* port){
	
	// create a socket 
	int sockID;	
	if ((sockID=socket(AF_INET,SOCK_DGRAM,0)) < 0) {
		perror("socket");	
		exit(1);
	}
	
	if(flag == RECEIVE){
		
		// set processes to reuse the socket in TIMEWAIT
		u_int yes = 1;
		setsockopt(sockID,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
		#ifdef __APPLE__
			setsockopt(sockID,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof(yes));
		#endif
	
		
		// bind the socket
		struct sockaddr_in serverAddress;
		bzero((char *) &serverAddress, sizeof(serverAddress));
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_addr.s_addr = INADDR_ANY;
		serverAddress.sin_port = htons(atoi(port));
		
		if (bind(sockID, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
			perror("bind");
			exit(1);
		}			
		
		struct ip_mreq mreq;	
		inet_pton(AF_INET, ipv4address, &(mreq.imr_multiaddr.s_addr));	
		mreq.imr_interface.s_addr=htonl(INADDR_ANY);
		
		if (setsockopt(sockID,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0) {
			perror("setsockopt");
			exit(1);
		}		
	}
	
	return sockID;
}

void prepareDnsMessage(int sockID, char* query, char* type){
		
	// prepare the header section
				
			dns.h.qdcount = htons(1);	
			dns.h.ancount = htons(0);	
			dns.h.nscount = htons(0);	
			dns.h.arcount = htons(0);	
	
	// prepare the question section
	
			// prepare qname
			int i,offset = 0;
			for (i=0; i<strlen(query); i++) {
				if (query[i] == '.'){
					if (offset){
						dns.nonheader[offset+1] = i-offset-1;
						strncpy(dns.nonheader+offset+2, query+offset+1, i-offset-1);
					}
					else{
						dns.nonheader[0] = i - offset;
						strncpy(dns.nonheader+1, query, i-offset);
					}
					offset = i;					
				}				
			}

			// check if query ending with a dot
			if(offset != i-1){
				dns.nonheader[offset+1] = i-offset-1;
				strncpy(dns.nonheader+offset+2, query+offset+1, i-offset-1);
				offset = i+2;
			}else{
				offset = i+1;
			}
	
			// prepare qtype|qclass
			
			char *iter;
			for (iter = type; *iter != '\0'; ++iter)
				*iter = tolower(*iter);
			
			if (!strcmp(type,"a"))
					question.qtype = htons(1);
			else if (!strcmp(type, "aaaa"))
					question.qtype = htons(28); 
			else if (!strcmp(type, "srv"))
					 question.qtype = htons(33);
			else if (!strcmp(type,"ptr"))
					question.qtype = htons(12);
			else if (!strcmp(type,"txt"))
					question.qtype = htons(16);
			else if (!strcmp(type,"any"))
					question.qtype = htons(255);
			
			question.qclass = htons(1);	
			memmove(dns.nonheader+offset, &question, sizeof(question));	
}

void sendDatagram(int sockID, char* ipv4address, char* port){
	
	struct sockaddr_in serverAddress;
	bzero((char *) &serverAddress, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;	
	inet_pton(AF_INET, ipv4address, &(serverAddress.sin_addr.s_addr));
	serverAddress.sin_port = htons(atoi(port));
	
	sendto(sockID, (char*)&dns, 512, 0, (struct sockaddr *) &serverAddress, sizeof(serverAddress));	
	close(sockID);
}

int echoQName(char** name, int flag, char* save){
	
	int index = 0;	
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
			echoQName(&qname, flag, save);
			return(1);
		}
		
		while (j < length){
			(*name)++; 			
			if(flag == PRINT_YES)
				printf("%c",**name);
			if(save != NULL)
				save[index++] = **name;
			j++;
		}		
		(*name)++;	
		if(flag == PRINT_YES)
			printf(".");
		if(save != NULL)
			save[index++] = '.';
	}	
	return(0);	
}

void receiveResults(int sockID, char* query, char* qtype){
	
	struct sockaddr_in clientAddress;	
	unsigned int clientAddressLength = sizeof(clientAddress);
	int ifFound = 0;	
	
	printf("\n\nQUESTION SECTION:\n");
	
	printf("%s", query);
	printf("\t\tIN\t\t");
	for (; (*qtype)!='\0'; qtype++)
		printf("%c", toupper(*qtype)); 		
	
	do{
		bzero(buffer,512);		
		if (recvfrom(sockID, buffer, sizeof(buffer), 0 , (struct sockaddr *) &clientAddress, &clientAddressLength) < 0) {
			perror("recvfrom");
			exit(1);		
		}
		
		/* move ahead of header section */
		mydns = (struct dnsMessage *) buffer;
		char* qname = mydns->nonheader;
		int k, l;
		
		/* move ahead of question section */
		for (k=1; k<=ntohs(mydns->h.qdcount); k++) {
			
			int flag = echoQName(&qname, PRINT_NO, NULL);
			
			// check if returned from message compression
			if(flag == 1)
				qname = qname + 2;
			else
				qname++;			
			qname = qname + 4;
		}
		
		/* read the resource records */
		for (l=1; l<=3; l++){
			unsigned short count, ifPrint = 0;
			switch (l) {
				case 1:
					count = ntohs(mydns->h.ancount);					
					break;
				case 2:
					count = ntohs(mydns->h.nscount);					
					break;
				case 3:
					count = ntohs(mydns->h.arcount);
					break;
			}		
			for (k=1; k<=count; k++) {	
				
				char *rname = malloc(sizeof(char) * strlen(query));
				char *offset = qname;
				echoQName(&offset, PRINT_NO, rname);
				
				if(!strncmp(query, rname, strlen(query))){
					
					char* offset = qname;
					int flag = echoQName(&qname, PRINT_NO, NULL);					
					if (flag == 1)
						qname = qname + 2;
					else
						(qname)++;
					
					resourceRecord = (struct fixedResourceRecord *) qname;
					
					if((ntohs(resourceRecord->type) == ntohs(question.qtype)) || ntohs(question.qtype) == 255){
						
						if(ifPrint==0){
							switch (l) {
								case 1:
									printf("\n\nANSWER SECTION:\n");
									break;
								case 2:
									printf("\n\nAUTHORITY SECTION:\n");
									break;
								case 3:
									printf("\n\nADDITIONAL SECTION:\n");								
							}					
							ifPrint = 1;
						}									
						echoQName(&offset, PRINT_YES, NULL);				
						
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
								echoQName(&ptr, PRINT_YES, NULL);
								break;
							default:
								printf("\t\tUNKNOWN");
						}			
						qname = qname + ntohs(resourceRecord->rdlength);	
						
						printf("\n");				
						ifFound = 1;
					}
					else{
						qname = qname + 10;
						qname = qname + ntohs(resourceRecord->rdlength);
					}
				}						
			}	
		}	
	}while(!ifFound);
	
	printf("\n\n");
}

int main(int argc, char *argv[]){
	
	if (argc != 5){
		printf("usage: querier ip port name type\n");
		exit(1);
	}
	
	int ipv4SockID = createIPv4Socket(SEND, NULL, NULL);
	
	prepareDnsMessage(ipv4SockID, argv[3], argv[4]);
	
	sendDatagram(ipv4SockID, argv[1], argv[2]);	
	
	ipv4SockID = createIPv4Socket(RECEIVE, argv[1], argv[2]);
	
	receiveResults(ipv4SockID, argv[3], argv[4]);	
	
	close(ipv4SockID);
	
	return 0;
}
