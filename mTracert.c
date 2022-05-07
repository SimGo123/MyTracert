/*
Program to trace a packet's way through the internet from its source to its destination.
Should work similar to traceroute (Linux) / tracert (Windows).
---
Mechanism:
A UDP packet with a low TTL (time to live) is sent to the destination.
Each hop (a server or whatever) on the way decreases the TTL.
When the TTL has reached 0 the hop usually sends us an ICMP with type 'time exceeded' (11).
So to trace a packet's way we start by sending UDP packets the same way and extract
the sender's IP from the incoming ICMP packet.
We start with a TTL of 1 and than increment it in the next iteration.
The problems are:
- We don't know if an incoming ICMP packet was really sent from one of the hops or if it
  is unrelated. So we check the copy of the UDP packet we originally sent which is contained in
  the ICMP packet. But the data we sent along isn't always present, so we check if the lengths
  of the UDP packet match.
- Not every hop sends an ICMP packet back to us. So we try again till we can be sure we haven't
  missed anything.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "ProtocolHelper.h"
#include "DNSHelper.h"
#include "PacketHelper.h"

/* Quite irrelevant. The target host will most likely send back an ICMP packet 
with type 3 (unreachable) if a packet finally reaches its destination. */
#define UDP_DEST_PORT 33456
#define MAXLINE 1024

/* Max number of hops to try to reach */
#define MAX_TTL 30
#define MAX_RESENDS 5
#define RECV_TIMEOUT_MCROSEC 300000     /* 0.3 sec */

char *UDP_CONTENT_PREFIX = "mTracert";
char *NO_RESPONSE_PLACEHOLDER = "***";

/* Print n characters (if n is big enough also after '\0') for debugging purposes */
void printNchars(u_int8_t *ptr, int n)
{
    for (int i = 0; i < n; ++i)
    {
        printf("%c\t\t%u\t\t0x%x\n", *(ptr + i), *(ptr + i), *(ptr + i));
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Trace the path of network packets to a destination\n");
        printf("Syntax:\nmTracert [ipAddr or hostname]\n");
        exit(EXIT_FAILURE);
    }

    /* Try to find/verify destination IP by DNS lookup - works for host & ip address */
    char *destinationIp;
    if ((destinationIp = dns_lookup(argv[1])) == NULL)
    {
        printf("You didn't pass a valid hostname/IP-address\n");
        exit(EXIT_FAILURE);
    }

    int udpSockFd;
    char buffer[MAXLINE];
    struct sockaddr_in sendFromAddr, destinationAddr;

    /* Create the udp socket */
    if ((udpSockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* ICMP socket - requires elevated privileges */
    int icmpSockFd;
    if ((icmpSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* Set timeout for the ICMP socket */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RECV_TIMEOUT_MCROSEC;
    setsockopt(icmpSockFd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    for (int ttl = 1; ttl <= MAX_TTL; ++ttl)
    {
        /* Set TTL for outgoing UDP packets */
        setsockopt(udpSockFd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        /* Set the UDP protocol content */
        char *content = (char *)malloc(strlen(UDP_CONTENT_PREFIX) + ttl + 1);
        memcpy(content, UDP_CONTENT_PREFIX, strlen(UDP_CONTENT_PREFIX) + 1);
        for (int j = 0; j < ttl; ++j)
        {
            *(content + strlen(UDP_CONTENT_PREFIX) + j) = 'S';
        }
        *(content + strlen(UDP_CONTENT_PREFIX) + ttl) = '\0';

        /* Was a matching ICMP packet found? */
        int icmpMatch = 0;

        /* Try again till correct ICMP packet gets received or the limit is reached */
        for (int j = 0; j < MAX_RESENDS; ++j)
        {
            packet_sendto(udpSockFd, content, destinationIp, UDP_DEST_PORT, MSG_CONFIRM);

            /* Try recieving packet from hop via ICMP */
            struct sockaddr r_addr;
            int addr_len = sizeof(r_addr);
            ssize_t recvdLen = recvfrom(icmpSockFd, (char *)buffer, MAXLINE, 0,
                                        (struct sockaddr *)&r_addr, &addr_len);
            /* Most likely because of timeout -> send again */
            if (recvdLen < 0)
            {
                continue;
            }
            buffer[recvdLen] = '\0';

            /* 
            The expected structure is: 
                IP packet containing ICMP packet containing IP packet containing 
                a copy of our originally sent UDP packet.
            */
            
            ipv4_data *outerIpData = extractFromIpPacket(buffer);

            if (outerIpData->validIPv4 == 1 && outerIpData->protocol == ICMP_PROT_NR)
            {
                icmp_data *icmp_data = extractFromIcmpPacket(outerIpData->optionalData);
                ipv4_data *innerIpData = icmp_data->ipData;
                if ((innerIpData->validIPv4 == 1 
                        && icmp_data->type == ICMP_TYPE_TIME_EXCEEDED 
                        && innerIpData->protocol == UDP_PROT_NR)
                    /* Packet is from destination and port is unreachable -> dest reached */
                    || (icmp_data->type == ICMP_TYPE_UNREACHABLE 
                        && strncmp(destinationIp, outerIpData->source, strlen(destinationIp)) == 0))
                {
                    udp_data *udpData = extractFromUdpPacket(innerIpData->optionalData);
                    /* Packet length matches in sent UDP and in recieved UDP packet copy */
                    if (udpData->length - UDP_HEADER_LEN == strlen(UDP_CONTENT_PREFIX) + ttl)
                    {
                        icmpMatch = 1;
                        break;
                    }
                }
            }
        }
        /* Add extra space if ttl is just one digit for formatting reasons */
        char *ttlFormatString = (char *)malloc(3 * sizeof(char));
        (ttl < 10) ? sprintf(ttlFormatString, " %d%c", ttl, '\0') 
                    : sprintf(ttlFormatString, "%d%c", ttl, '\0');

        /* Only print host and ip if icmp packet corresponds to a sent UDP packet */
        if (icmpMatch)
        {
            ipv4_data *ipData = extractFromIpPacket(buffer);
            icmp_data *icmpData = extractFromIcmpPacket(ipData->optionalData);

            char *hostName = reverse_dns_lookup(ipData->source);
            printf("%s %s - %s\n", ttlFormatString, hostName, ipData->source);

            /* Destination probably reached */
            if (icmpData->type == ICMP_TYPE_UNREACHABLE)
            {
                return EXIT_SUCCESS;
            }
        }
        else
        {
            printf("%s %s\t\t\t%s\n", ttlFormatString, NO_RESPONSE_PLACEHOLDER, NO_RESPONSE_PLACEHOLDER);
        }
    }

    return 0;
}