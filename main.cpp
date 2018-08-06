#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include "printdata.hpp"

using namespace std;

#define ETHER_BROADCAST 0xFFFFFFFF
#define INET_ADDR_LEN 6
#define ARP_REQUEST 1

uint32_t BROADCAST = ETHER_BROADCAST;

void usage()
{
    cout<<"./send_arp <device> <sender_ip>"<<endl;
    exit(1);
}

bool chkArgc(int argc)
{
    if(argc !=3)
        return false;

    return true;
}


struct NetInfo{
    Mac mac;
    Ip ip;
};

int sendRequestARP(const pcap_t *pcd, const uint32_t *ip, const uint8_t *myMac);
bool getRemoteHWaddr(const uint32_t *ip, const uint8_t *myMac, uint8_t* macBuf);


int main(int argc, char* argv[])
{
    if(!chkArgc(argc))
        usage();
    //set Device variable
    char* dev =argv[1];

    NetInfo host;
    NetInfo sender;

    //Get my MAC addr use socket IO
    host.mac.getMyMac(dev);
//    sender.mac=

    return 0;
}


int sendRequestARP(const pcap_t* pcd, const uint32_t *ip, const uint8_t *myMac)
{
    static struct ether_header eth;

    //set ETHER_HEADER

    memcpy(eth.ether_dhost,&BROADCAST,ETHER_ADDR_LEN);
    memcpy(eth.ether_shost,myMac,ETHER_ADDR_LEN);
    eth.ether_type=ETHERTYPE_ARP;

    static struct ether_arp arp;

    arp.ea_hdr.ar_hrd = ntohs(1);                //set Hardware Type Ethernet
    arp.ea_hdr.ar_pro = ntohs(ETHERTYPE_IP);     //set ARP type to IP
    arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;          //set Hardware length to 6(MAC Addr)
    arp.ea_hdr.ar_pln = INET_ADDR_LEN;           //set Protocol length to 4(IPv4 Addr)
    arp.ea_hdr.ar_op = ARP_REQUEST;              //set OPCODE to REQUEST

    //return 0 on success if not -1
    return pcap_sendpacket(pcd, &eth, sizeof(eth))

}
bool getRemoteHWaddr(const uint32_t *ip,const uint8_t *myMac, uint8_t *macBuf)
{
    sendRequestARP(ip,myMac);


}


