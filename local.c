/*
 * Copyright 2019 Ian Pilcher <arequipeno@gmail.com>
 *
 * This program is free software.  You can redistribute it or modify it under
 * the terms of version 2 of the GNU General Public License (GPL), as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY -- without even the implied warranty of MERCHANTIBILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the text of the GPL for more details.
 *
 * Version 2 of the GNU General Public License is available at:
 *
 *   http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <unistd.h>

#define FBR_STATIC_ASSERT(x)    _Static_assert((x), "static assertion failed")


struct fbr_addr {
	sa_family_t		family;
	union {
		struct in_addr	in;
		struct in6_addr	in6;
	};
};

/* Verify fbr_addr wire format */
FBR_STATIC_ASSERT(sizeof(sa_family_t) == 2);
FBR_STATIC_ASSERT(sizeof(struct in_addr) == 4);
FBR_STATIC_ASSERT(sizeof(struct in6_addr) == 16);
FBR_STATIC_ASSERT(offsetof(struct fbr_addr, in) == 4);
FBR_STATIC_ASSERT(offsetof(struct fbr_addr, in6) == 4);

union fbr_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
};

FBR_STATIC_ASSERT(offsetof(union fbr_sockaddr, sin.sin_port)
			== offsetof(struct sockaddr_in6, sin6_port));


static void fbr_parse_ip(struct fbr_addr *const dst, const char *const src)
{
	if (inet_pton(AF_INET, src, &dst->in.s_addr) == 1) {
		dst->family = AF_INET;
		return;
	}
	
	if (inet_pton(AF_INET6, src, &dst->in6.s6_addr) == 1) {
		dst->family = AF_INET6;
		return;
	}
	
	fprintf(stderr, "Invalid IP address: %s\n", src);
	exit(EXIT_FAILURE);
}

static void fbr_parse_remote(union fbr_sockaddr *const remote,
			     const char *const src)
{
	struct fbr_addr dst;
	
	fbr_parse_ip(&dst, src);
	
	if (dst.family == AF_INET) {
		remote->sin.sin_family = AF_INET;
		remote->sin.sin_addr.s_addr = dst.in.s_addr;
	}
	else {
		remote->sin6.sin6_family = AF_INET6;
		memcpy(&remote->sin6.sin6_addr, &dst.in6, sizeof(dst.in6));
	}
}

static uint16_t fbr_parse_port(const char *const arg)
{
	unsigned long port;
	char *endptr;
	
	if (!isdigit(*arg)) {
		fprintf(stderr, "Non-digit in port: %s\n", arg);
		exit(EXIT_FAILURE);
	}
	
	errno = 0;
	port = strtoul(arg, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || port > UINT16_MAX) {
		fprintf(stderr, "Invalid port: %s\n", arg);
		exit(EXIT_FAILURE);
	}
	
	return (uint16_t)port;
}

int main(const int argc, const char *const *const argv)
{
	const struct sockaddr_in sport = {
		.sin_family	= AF_INET,
		.sin_port	= htons(789),
		.sin_addr	= { .s_addr = INADDR_ANY }
	};

	union fbr_sockaddr remote;
	struct fbr_addr ip;
	ssize_t sent;
	int sockfd;

	if (argc != 4) {
		fputs("Incorrect number of arguments\n", stderr);
		exit(EXIT_FAILURE);
	}
	
	fbr_parse_ip(&ip, argv[1]);
	fbr_parse_remote(&remote, argv[2]);
	remote.sin.sin_port = htons(fbr_parse_port(argv[3]));
	
	if ((sockfd = socket(remote.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (bind(sockfd, (const void *)&sport, sizeof sport) != 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	
	ip.family = htons(ip.family);
	
	sent = sendto(sockfd, &ip, sizeof ip, 0, &remote.sa, sizeof remote);
	if (sent < 0) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
	
	if (sent != sizeof ip) {
		fprintf(stderr, "Sent %zd bytes; expected %zu\n", sent,
			sizeof ip);
		exit(EXIT_FAILURE);
	}
	
	if (close(sockfd) < 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}
	
	return EXIT_SUCCESS;
}
