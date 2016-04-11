#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
using namespace std;

struct sockaddr_in localaddr, peeraddr;
int sockfd = socket(AF_INET,SOCK_DGRAM,0);
struct timeval pre_time;
struct timeval cur_time;
unsigned int pkg_num = 0;

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    if(header->caplen != header->len)
    {
	printf("this captured pkg length is not equal with the actual real pkg length!\n");
	return;
    }
    if(pkg_num == 0)
    {
	sendto(sockfd,pkt_data+14+20+8,header->len-42,0,(struct sockaddr *)&peeraddr,sizeof(peeraddr));
        pkg_num++;	
	pre_time = header->ts;
    }
    else
    {
	cur_time = header->ts;
	unsigned int interval = (cur_time.tv_sec - pre_time.tv_sec) * 1000 * 1000 + (cur_time.tv_usec - pre_time.tv_usec);
        usleep(interval);
        sendto(sockfd,pkt_data+14+20+8,header->len-42,0,(struct sockaddr *)&peeraddr,sizeof(peeraddr));  
	pkg_num++;
        pre_time = cur_time;

    }
}
void usage(char *program)
{
    printf("usage:\n");
    printf("%s pcap_file_name src_ip src_port dst_ip dst_port\n",program);
}
int main(int argc, char **argv)
{
    if(argc != 6)
    {
        printf("wrong parmeters, exit!\n");
        usage(argv[0]);
        return 0;
    }
    usage(argv[0]);

    bzero(&pre_time,sizeof(pre_time));
    bzero(&cur_time,sizeof(cur_time));

    int local_port = atoi(argv[3]);
    bzero(&localaddr, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(local_port);
    localaddr.sin_addr.s_addr = inet_addr(argv[2]);
    if(bind(sockfd,(struct sockaddr *)&localaddr,sizeof(struct sockaddr)) == -1)
    {
	close(sockfd);
	printf("error when trying to bind local ip/port");
	return -1;
    }
    bzero(&peeraddr, sizeof(peeraddr));
    peeraddr.sin_family = AF_INET;
    int peer_port = atoi(argv[5]);
    peeraddr.sin_port = htons(peer_port);
    peeraddr.sin_addr.s_addr = inet_addr(argv[4]);

    pcap_t *fp;
    const char *filename = argv[1];
    char errbuf[50];
    if ((fp = pcap_open_offline(filename, errbuf)) == NULL)
    {
        printf("unable to open pcap file");
        return -1;
    }
    else
    { 
        printf("sending .....\n");
    	pcap_loop(fp, 0, dispatcher_handler, NULL);
    }
    pcap_close(fp);
    close(sockfd);
    printf("done, total sent pkg number: %d\n", pkg_num);
}
