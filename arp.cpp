#include "arp.h"
#include <cstring>
#include <netinet/in.h>

Arp::Arp()
{

}

void Arp::initEth(uint8_t *src, uint8_t *dest, uint16_t type)
{
    memcpy(eth.ether_dhost,dest,ETHER_ADDR_LEN);
    memcpy(eth.ether_shost,src,ETHER_ADDR_LEN);
    eth.ether_type = htons(type);
}


void Arp::initRequestARP(uint8_t *src_HW,uint32_t* src_protocol, uint32_t* dest_protocol)
{
    arp.ea_hdr.ar_hrd = ntohs(1);                //set Hardware Type Ethernet
    arp.ea_hdr.ar_pro = ntohs(ETHERTYPE_IP);     //set ARP type to IP
    arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;          //set Hardware length to 6(MAC Addr)
    arp.ea_hdr.ar_pln = INET_ADDR_LEN;           //set Protocol length to 4(IPv4 Addr)
    arp.ea_hdr.ar_op = ARP_REQUEST;              //set OPCODE to REQUEST


    memcpy(&arp.arp_sha, src_HW, ETHER_ADDR_LEN);       //set Sender MAC Addr to src
    memcpy(&arp.arp_tha, &ARP_UNKNOWN, ETHER_ADDR_LEN);      //set Target MAC Addr to 00:00:00:00:00:00
    memcpy(&arp.arp_spa, src_protocol, INET_ADDR_LEN);  //set Sender IP Addr to src
    memcpy(&arp.arp_tpa, dest_protocol, INET_ADDR_LEN); //set Target IP Addr to dest



}
