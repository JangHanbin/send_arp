#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "jpcaplib.h"
#include "mac.h"
#include "ip.h"
#include "arp.h"
#include "printdata.hpp"

using namespace std;

#define ETHER_BROADCAST 0xFFFFFFFF


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

bool getRemoteHWaddr(pcap_t *pcd, const uint32_t *ip, uint8_t* mac_buf);


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
    host.ip.getMyIp(dev);

    //Set Sender IP Addr to argv[2]
    sender.ip=argv[2];

    //init ARP request packet to get sender MAC addr
    Arp arp_request_packet;

    arp_request_packet.initEth(host.mac.retnMac(),(uint8_t*)(&BROADCAST),ETHERTYPE_ARP);
    arp_request_packet.initRequestARP(host.mac.retnMac(),host.ip.retnIP(), sender.ip.retnIP());

    pcap_t*pcd = pOpen(dev);
    getRemoteHWaddr(pcd, host.ip.retnIP(),host.mac.retnMac());

    return 0;
}



bool getRemoteHWaddr(pcap_t* pcd, const uint32_t *ip, uint8_t *mac_buf)
{
    uint8_t* packet;
    int data_len;
    struct ether_arp *arp;
    while(recvPacket(pcd,&packet,data_len))
    {
        if(parseEther(&packet,data_len,ETHERTYPE_ARP))
        {
            arp = (struct ether_arp *)packet;
            //if ARP Sender IP equals IP
            if(memcmp(arp->arp_spa,ip,INET_ADDR_LEN))
            {
                //copy MAC Addr to macBuf
                memcpy(mac_buf, arp->arp_sha,ETHER_ADDR_LEN);
                return true;
            }
        }
    }

   return false;

}


