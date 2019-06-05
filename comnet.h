#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h> /* See NOTES */
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols  */

#include <arpa/inet.h> /* for htons function */
#include <unistd.h>    /* for close function */

#include <sys/ioctl.h>
#include <net/if.h>

#include <sys/time.h>

#include <netdb.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <signal.h>

unsigned char my_MAC[6];
unsigned char my_IP[4];
unsigned char NETMASK[4];
unsigned int Metric;
unsigned int MTU;

unsigned char dest_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char dest_IP[4] = {0x00, 0x00, 0x00, 0x00};

unsigned char source_MAC[6];
unsigned char source_IP[4];

unsigned char MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char IP[4] = {0x00, 0x00, 0x00, 0x00};

unsigned char clear_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char clear_IP[4] = {0x00, 0x00, 0x00, 0x00};

unsigned char frame_s[1514], frame_r[1514];
unsigned char bro_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char ethertype_ARP[2] = {0x08, 0x06};
unsigned char ethertype_ip[2] = {0x08, 0x00};
unsigned char HW[2] = {0x00, 0x01};
unsigned char PR[2] = {0x08, 0x00};
unsigned char LDH[1] = {0x06};
unsigned char LDP[1] = {0x04};
unsigned char epcode_ARP_request[2] = {0x00, 0x01};
unsigned char epcode_ARP_replay[2] = {0x00, 0x02};

unsigned char alameda_MAC_LAN[6] = {0x00, 0x8c, 0xfa, 0x7c, 0xc0, 0xdf};
unsigned char alameda_MAC_WLAN[6] = {0xa4, 0xdb, 0x30, 0x7b, 0xaf, 0x77};

unsigned char dest_port[2] = {0x00, 0x00};
unsigned char H_TCP[111];
unsigned char H_IP[111];

struct timeval start, end;
long mtime, seconds, useconds;

int getData(int sd);
void ARPframe(unsigned char *frame, unsigned char *s_MAC, unsigned char *s_IP, unsigned char *d_MAC, unsigned char *d_IP);
void frame(unsigned char *frame);
void sendFrame(int sd, int index, unsigned char *frame, int frame_size);
void printFrame(unsigned char *frame, int size);
void printARPinfo(unsigned char *frame, int size);
void receiveFrame(int sd, unsigned char *frame);
void stringToIP(char *ip_s);
char *IPToString(unsigned char *ip);

void gratARPreply(unsigned char *frame, unsigned char *s_MAC, unsigned char *d_MAC, unsigned char *d_IP);
void gratARPrequest(unsigned char *frame, unsigned char *d_MAC, unsigned char *d_IP);

int isLocalIP(unsigned char *d_IP);
int getGatewayIP(unsigned char *gateway_IP);
void receiveARPFrame(int sd, unsigned char *frame);
void TCP_Scan(int sd, int index);
void TCPframe(unsigned char *frame, unsigned int port);
unsigned short checksum(unsigned char *buff, int bufflen);
int TCPPortIsOpen(int sd, unsigned char *frame, unsigned int port);

#define BUFFER_SIZE 4096
#define MAX_PORTS 100