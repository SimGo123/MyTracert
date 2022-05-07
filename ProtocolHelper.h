/*
Helps extracting data from IPv4, UDP and ICMP headers from raw packet bytes.
They can be combined: icmp_data->ipData points to ipv4_data, and ipv4_data->optional data
could include another protocol.
*/
#ifndef PROT_HLPR
#define PROT_HLPR

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ICMP_PROT_NR 1
#define UDP_PROT_NR 17

/* Converts the bytes in a 4 byte integer to an ip address */
char *intToIpAddr(u_int32_t number)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = number;
    return inet_ntoa(ip_addr);
}

/* Do a 'pancake-flip' of the bytes at the start (<n/2) with the bytes at the end and vice versa */
void changeEndianism(void *toChange, int n)
{
    for (int i = 0; i < n / 2; ++i)
    {
        void *swapTmp = malloc(1);
        memcpy(swapTmp, toChange + n - i - 1, 1);
        memcpy(toChange + n - i - 1, toChange + i, 1);
        memcpy(toChange + i, swapTmp, 1);
    }
}

typedef struct ipv4_data
{
    int validIPv4;

    u_int8_t inetHeaderLength;
    u_int8_t diffServicesField;
    u_int16_t totalLength;
    u_int16_t ident;
    u_int16_t flags;
    u_int8_t ttl;
    u_int8_t protocol;              /* The type of the protocol contained in the optional data */
    u_int16_t headerChecksum;
    char *source;
    char *destination;
    char *optionalData;

} ipv4_data;

/* Converts bytes to an IPv4 header. Users should check if ipv4_data->valid == 1 */
ipv4_data *extractFromIpPacket(char *rawPacket)
{
    ipv4_data *extrData = (ipv4_data *)malloc(sizeof(ipv4_data));

    if (rawPacket[0] >> 4 != 4)
    {
        extrData->validIPv4 = 0;
        return extrData;
    }

    extrData->validIPv4 = 1;

    u_int16_t totalLength, ident, flags, headerChecksum;
    u_int8_t ttl, protocol;
    u_int32_t source, destination;

    extrData->inetHeaderLength = rawPacket[0] & 0xf;

    extrData->diffServicesField = rawPacket[1];

    memcpy(&totalLength, rawPacket + 2, 2);
    changeEndianism(&totalLength, 2);
    extrData->totalLength = totalLength;

    memcpy(&ident, rawPacket + 4, 2);
    changeEndianism(&ident, 2);
    extrData->ident = ident;

    memcpy(&flags, rawPacket + 6, 2);
    changeEndianism(&flags, 2);
    extrData->flags = flags;

    memcpy(&ttl, rawPacket + 8, 1);
    extrData->ttl = ttl;

    memcpy(&protocol, rawPacket + 9, 1);
    extrData->protocol = protocol;

    memcpy(&headerChecksum, rawPacket + 10, 2);
    changeEndianism(&headerChecksum, 2);
    extrData->headerChecksum = headerChecksum;

    memcpy(&source, rawPacket + 12, 4);
    char *ipAddrPtr = intToIpAddr(source);
    extrData->source = (char *)calloc(strlen(ipAddrPtr) + 1, sizeof(char *));
    memcpy(extrData->source, ipAddrPtr, strlen(ipAddrPtr) + 1);

    memcpy(&destination, rawPacket + 16, 4);
    ipAddrPtr = intToIpAddr(destination);
    extrData->destination = (char *)calloc(strlen(ipAddrPtr) + 1, sizeof(char *));
    memcpy(extrData->destination, ipAddrPtr, strlen(ipAddrPtr) + 1);

    extrData->optionalData = rawPacket + 20;

    return extrData;
}

void printIPv4Data(ipv4_data *ipData)
{
    printf("\nIPv4 Data Printout:\n");
    printf("valid IPv4: %s\n", (ipData->validIPv4 == 1) ? "true" : "false");

    printf("inet header len: %d\n", ipData->inetHeaderLength);
    printf("diff services field: %d\n", ipData->diffServicesField);
    printf("total len: %d\n", ipData->totalLength);
    printf("ident: %d\n", ipData->ident);
    printf("flags: %d\n", ipData->flags);
    printf("ttl: %d\n", ipData->ttl);
    char *protName = (ipData->protocol == ICMP_PROT_NR) ? "ICMP" : ((ipData->protocol == UDP_PROT_NR) ? "UDP" : "");
    printf("protocol: %d (%s)\n", ipData->protocol, protName);
    printf("header checksum: %d\n", ipData->headerChecksum);

    printf("src: %s\n", ipData->source);
    printf("dst: %s\n", ipData->destination);

    printf("opt: %s\n", ipData->optionalData);
    printf("\n");
}

#define UDP_HEADER_LEN 8

typedef struct udp_data
{
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int16_t length;
    u_int16_t checksum;
    char *data;
} udp_data;

udp_data *extractFromUdpPacket(char *rawPacket)
{
    u_int16_t source_port, destination_port, length, checksum;

    udp_data *extrData = (udp_data *)malloc(sizeof(udp_data));

    memcpy(&source_port, rawPacket, 2);
    changeEndianism(&source_port, 2);
    extrData->source_port = source_port;

    memcpy(&destination_port, rawPacket + 2, 2);
    changeEndianism(&destination_port, 2);
    extrData->destination_port = destination_port;

    memcpy(&length, rawPacket + 4, 2);
    changeEndianism(&length, 2);
    extrData->length = length;

    memcpy(&checksum, rawPacket + 6, 2);
    changeEndianism(&checksum, 2);
    extrData->checksum = checksum;

    extrData->data = (char *)calloc(length - UDP_HEADER_LEN + 1, sizeof(char));
    memcpy(extrData->data, rawPacket + UDP_HEADER_LEN, length - UDP_HEADER_LEN);

    return extrData;
}

void printUdpData(udp_data *udpData)
{
    printf("\nUDP Data Printout:\n");
    printf("source port: %d\n", udpData->source_port);
    printf("destination port: %d\n", udpData->destination_port);
    printf("len: %d\n", udpData->length);
    printf("checksum: %d\n", udpData->checksum);
    printf("data: %s\n", udpData->data);
    printf("\n");
}

#define ICMP_TYPE_UNREACHABLE 3
#define ICMP_TYPE_TIME_EXCEEDED 11

typedef struct icmp_data
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t headerChecksum;

    ipv4_data *ipData;
} icmp_data;

icmp_data *extractFromIcmpPacket(char *rawPacket)
{
    u_int8_t type, code;
    u_int16_t headerChecksum;

    icmp_data *extrData = (icmp_data *)malloc(sizeof(icmp_data));

    memcpy(&type, rawPacket, 1);
    extrData->type = type;

    memcpy(&code, rawPacket + 1, 1);
    extrData->code = code;

    memcpy(&headerChecksum, rawPacket + 2, 2);
    changeEndianism(&headerChecksum, 2);
    extrData->headerChecksum = headerChecksum;

    extrData->ipData = extractFromIpPacket(rawPacket + 8);

    return extrData;
}

void printIcmpData(icmp_data *icmpData)
{
    printf("\nICMP Data Printout:\n");
    printf("type: %d\n", icmpData->type);
    printf("code: %d\n", icmpData->code);
    printf("headerChecksum: %d\n", icmpData->headerChecksum);
    printf("\n");
}

#endif