#ifndef PCKT_HLPR
#define PCKT_HLPR

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Simplification of socket's sendto */
ssize_t packet_sendto(int sockFd, char *content, char *destIp, int destPort, int msg_flags)
{
    struct sockaddr_in destAddr;

    memset(&destAddr, 0, sizeof(destAddr));

    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(destIp);
    destAddr.sin_port = htons(destPort);

    return sendto(sockFd, (const char *)content, strlen(content),
                  msg_flags, (const struct sockaddr *)&destAddr, sizeof(destAddr));
}

#endif