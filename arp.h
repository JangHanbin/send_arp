#ifndef ARP_H
#define ARP_H

#include <netinet/ether.h>

#define INET_ADDR_LEN 4
#define ARP_REQUEST 1
#define ARP_REPLY 2

//ARP class must be alignment set to 1byte.
#pragma pack(push,1)

class Arp
{
    struct ether_header eth;
    struct ether_arp arp;

public:
    Arp();
    void initEth(uint8_t* src, uint8_t* dest, uint16_t type);
    void initRequestARP(uint8_t* src_HW, uint32_t *src_protocol, uint32_t *dest_protocol);
    void initReplyARP(uint8_t* src_HW, uint8_t* dest_HW, uint32_t *src_protocol, uint32_t *dest_protocol);


};

#pragma pack(pop)
#endif // ARP_H
