#include "jpcaplib.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include "printdata.hpp"




bool recvPacket(pcap_t* pcd, uint8_t **packetData,int& dataLen)
{

    const u_char *pkt_data;
    struct pcap_pkthdr *pktHeader;
    int valueOfNextEx;

    while(true)
    {
        valueOfNextEx=pcap_next_ex(pcd,&pktHeader,&pkt_data);

        switch (valueOfNextEx)
        {
            case 1:
                    *packetData=(uint8_t*)pkt_data;
                    dataLen=pktHeader->caplen;
                    return true;

            case 0:
                //cout<<"need a sec.. to packet capture"<<endl;
                continue;
            case -1:
                perror("pcap_next_ex function has an error!!");

                exit(1);

            case -2:
                cout<<"the packet have reached EOF!!"<<endl;
                exit(0);
            default:
                return false;
            }
    }
}

bool parseEther(uint8_t** data,int& dataLen,int type)
{
    struct ether_header *ep=(struct ether_header*)*data;

    if(ntohs(ep->ether_type)==type)
    {

        *data=*data+sizeof(struct ether_header);
        dataLen-=sizeof(struct ether_header);
        return true;
    }


    return false;
}

bool parseIP(uint8_t** data,int& dataLen, int type)
{

    struct iphdr *iph=(struct iphdr*)*data;

    if(iph->protocol==type)
    {

        *data=*data+(iph->ihl*4);
        dataLen-=(iph->ihl*4);
        return true;
    }


    return false;
}



bool parseTCPData(uint8_t **data, int &dataLen)
{
    struct tcphdr* tcph = (struct tcphdr*)*data;
    *data=*data+(tcph->doff*4);
    dataLen-=(tcph->doff*4);

    if(dataLen<=0)
        return false;
    else
        return true;


}


pcap_t *pOpen(char *device)
{
    pcap_t *pcd;
    if((pcd=pcap_open_live(device,BUFSIZ,0,1,errBuf))==NULL)
    {
        cout<<"Pcap Open Error!"<<endl;
        exit(1);
    }


    return pcd;
}



bool parseTCPOptions(uint8_t **data, int &dataLen)
{

    if((dataLen-20)>0)
    {
        *data=*data+20;
        dataLen-=20;
        return true;
    }

    return false;
}
