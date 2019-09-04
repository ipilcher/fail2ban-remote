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


#define _GNU_SOURCE		/* for vsyslog & sighandler_t */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <syslog.h>
#include <time.h>

#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/nfnetlink.h>

#include <libmnl/libmnl.h>


/*******************************************************************************
 * 
 * Data types
 * 
 ******************************************************************************/

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

/* Verify that port members overlap as expected */
FBR_STATIC_ASSERT(offsetof(union fbr_sockaddr, sin.sin_port)
			== offsetof(union fbr_sockaddr, sin6.sin6_port));



/*******************************************************************************
 * 
 * Logging
 * 
 ******************************************************************************/

#define FBR_MKSTR_INTERNAL(s)	#s
#define FBR_MKSTR(s)		FBR_MKSTR_INTERNAL(s)

#define FBR_DEBUG(...)	do {						       \
				if (fbr_verbose) {			       \
					fbr_msg(LOG_INFO, "DEBUG: " __FILE__   \
						":" FBR_MKSTR(__LINE__) ": "   \
						__VA_ARGS__);		       \
				}					       \
			}						       \
			while (0)
			

#define FBR_INFO(...)	fbr_msg(LOG_INFO, "INFO: " __FILE__ ":"		       \
				FBR_MKSTR(__LINE__) ": " __VA_ARGS__)

#define FBR_WARN(...)	fbr_msg(LOG_WARNING, "WARNING: " __FILE__ ":"	       \
				FBR_MKSTR(__LINE__) ": " __VA_ARGS__)

#define FBR_ERR(...)	fbr_msg(LOG_ERR, "ERROR: " __FILE__ ":"		       \
				FBR_MKSTR(__LINE__) ": " __VA_ARGS__)

#define FBR_FATAL(...)	do {						       \
				fbr_msg(LOG_ERR, "FATAL: " __FILE__ ":"	       \
					FBR_MKSTR(__LINE__) ": " __VA_ARGS__); \
				exit(EXIT_FAILURE);			       \
			}						       \
			while (0)
				
#define FBR_ABORT(...)	do {						       \
				fbr_msg(LOG_ERR, "FATAL: " __FILE__ ":"	       \
					FBR_MKSTR(__LINE__) ": " __VA_ARGS__); \
				abort();				       \
			}						       \
			while (0)
				
static _Bool fbr_log_stderr = 1;	/* Use stderr while parsing options */

__attribute__((format(printf, 2, 3)))
static void fbr_msg(const int priority, const char *const format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	
	if (fbr_log_stderr)
		vfprintf(stderr, format, ap);
	else
		vsyslog(priority, format, ap);
	
	va_end(ap);
}

/*
 * Utility functions to format IP (v4 or v6) addresses.  dst buffer size must be
 * at least INET6_ADDRSTRLEN.
 */

static const char *fbr_inet_ntop(const sa_family_t af, const void *const src,
				 char *const dst)
{
	if (inet_ntop(af, src, dst, INET6_ADDRSTRLEN) == NULL)
		FBR_ABORT("inet_ntop: %m\n");
	
	return dst;
}

static const char *fbr_format_sa(const union fbr_sockaddr *const sa,
				 char *const dst)
{
	sa_family_t af;
	
	af = sa->sa.sa_family;
	
	assert(af == AF_INET || af == AF_INET6);
	
	if (af == AF_INET)
		return fbr_inet_ntop(af, &sa->sin.sin_addr.s_addr, dst);
	else
		return fbr_inet_ntop(af, &sa->sin6.sin6_addr.s6_addr, dst);
}


/*******************************************************************************
 * 
 * Command-line options & parsing
 * 
 ******************************************************************************/

/*
 * Macro version of htons() for default port initializer
 */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

	#define HTONS(x)	((uint16_t)x)
	
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

	#define HTONS(x)	(((((uint16_t)x) & 0x00ff) << 8) 	       \
					| ((((uint16_t)x) & 0xff00) >> 8))
	
#else
	
	#error "unknown __BYTE_ORDER__"
	
#endif

/*
 * The options, some with default values
 */

static _Bool fbr_stderr_opt = 0;
static _Bool fbr_verbose = 0;
static const char *fbr_set4_name;
static const char *fbr_set6_name;
static union fbr_sockaddr fbr_listen = { .sin6 = { .sin6_port = HTONS(789) } };

__attribute__((noreturn))
static void fbr_help(const char *const exec, const int rc)
{
	printf("Usage: %s [-s|--stderr] [-v|--verbose] [-h|--help]\n"
	       "\t[-p|--port PORT] -l|--listen ADDRESS\n"
	       "\t-4|--ipv4-ipset IPV4_IPSET -6|--ipv6-ipset IPV6_IPSET\n",
	       exec);
	exit(rc);
}
	
__attribute__((noreturn))
static void fbr_parse_help(const char *const exec,
			   const char *arg __attribute__((unused)))
{
	fbr_help(exec, EXIT_SUCCESS);
}

static void fbr_parse_stderr(const char *exec __attribute__((unused)),
			     const char *arg __attribute__((unused)))
{
	fbr_stderr_opt = 1;
}

static void fbr_parse_verbose(const char *exec __attribute__((unused)),
			      const char *arg __attribute__((unused)))
{
	fbr_verbose = 1;
}

static void fbr_parse_set4(const char *const exec, const char *const arg)
{
	if (*arg == '\0' || strlen(arg) >= IPSET_MAXNAMELEN) {
		FBR_ERR("invalid IPv4 ipset name: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
	
	fbr_set4_name = arg;
}

static void fbr_parse_set6(const char *const exec, const char *const arg)
{
	if (*arg == '\0' || strlen(arg) >= IPSET_MAXNAMELEN) {
		FBR_ERR("invalid IPv6 ipset name: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
	
	fbr_set6_name = arg;
}

static void fbr_parse_port(const char *const exec, const char *const arg)
{
	unsigned long port;
	char *endptr;
	
	errno = 0;
	port = strtoul(arg, &endptr, 0);
	if (errno != 0 || *endptr != '\0' || port > UINT16_MAX) {
		FBR_ERR("invalid UDP port number: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
		
	fbr_listen.sin6.sin6_port = htons(port);
}

static void fbr_parse_addr(const char *const exec, const char *const arg)
{
	if (inet_pton(AF_INET, arg, &fbr_listen.sin.sin_addr) == 1) {
		fbr_listen.sin.sin_family = AF_INET;
		return;
	}
	
	if (inet_pton(AF_INET6, arg, &fbr_listen.sin6.sin6_addr) == 1) {
		fbr_listen.sin6.sin6_family = AF_INET6;
		return;
	}
	
	FBR_ERR("invalid IP address: %s\n", arg);
	fbr_help(exec, EXIT_FAILURE);
}
	
struct fbr_option {
	const char *	sopt;
	const char *	lopt;
	void		(*parse)(const char *exec, const char *arg);
	_Bool		arg;
	_Bool		called;
	_Bool		required;
};

static struct fbr_option fbr_options[] = {
	{ "-s", "--stderr",	fbr_parse_stderr,	0, 0, 0 },
	{ "-v", "--verbose",	fbr_parse_verbose,	0, 0, 0 },
	{ "-p", "--port",	fbr_parse_port,		1, 0, 0 },
	{ "-l", "--listen",	fbr_parse_addr,		1, 0, 1 },
	{ "-h", "--help",	fbr_parse_help,		0, 0, 0 },
	{ "-4", "--ipv4-ipset", fbr_parse_set4,		1, 0, 1 },
	{ "-6", "--ipv6-ipset", fbr_parse_set6,		1, 0, 1 },
	{ NULL, NULL,		0,			0, 0, 0 }
};

static _Bool fbr_arg_is_opt(const char *const arg,
			    const struct fbr_option *const opt)
{
	return strcmp(arg, opt->sopt) == 0 || strcmp(arg, opt->lopt) == 0;
}

static void fbr_parse_opt(const char *const exec, const char *const arg,
			  const struct fbr_option *const opt)
{
	if (opt->arg && arg == NULL) {
		FBR_ERR("option requires an argument: %s (%s)\n",
			opt->lopt, opt->sopt);
		fbr_help(exec, EXIT_FAILURE);
	}
	
	if (opt->called) {
		FBR_ERR("duplicate option: %s (%s)\n", opt->lopt, opt->sopt);
		fbr_help(exec, EXIT_FAILURE);
	}
	
	opt->parse(exec, arg);
}

static void fbr_dump_opts(void)
{
	char buf[INET6_ADDRSTRLEN];

	if (!fbr_verbose)
		return;
	
	FBR_DEBUG("successfully parsed command-line options\n");
	FBR_DEBUG("  log to stderr: %s\n",
		  fbr_log_stderr ? "true" : "false");
	FBR_DEBUG("  verbose: %s\n", fbr_verbose ? "true" : "false");
	FBR_DEBUG("  IP version: IPv%d\n",
		  fbr_listen.sa.sa_family == AF_INET ? 4 : 6);
	FBR_DEBUG("  listen address: %s\n", fbr_format_sa(&fbr_listen, buf));
	FBR_DEBUG("  listen port: %" PRIu16 "\n",
		  ntohs(fbr_listen.sin.sin_port));
	FBR_DEBUG("  IPv4 ipset name: %s\n", fbr_set4_name);
	FBR_DEBUG("  IPv6 ipset name: %s\n", fbr_set6_name);
}

static void fbr_parse_opts(const char *const *const argv)
{
	const char *const *argp;
	struct fbr_option *opt;
	
	for (argp = argv + 1; *argp != NULL; ++argp) {
		
		for (opt = fbr_options; opt->sopt != NULL; ++opt) {
			if (fbr_arg_is_opt(*argp, opt)) {
				argp += opt->arg;
				fbr_parse_opt(argv[0], *argp, opt);
				opt->called = 1;
				break;
			}
		}
		
		if (opt->sopt == NULL) {
			FBR_ERR("unknown option: %s\n", *argp);
			fbr_help(argv[0], EXIT_FAILURE);
		}
	}
	
	for (opt = fbr_options; opt->sopt != NULL; ++opt) {
		if (opt->required && !opt->called) {
			FBR_ERR("required option not present: %s (%s)\n",
				opt->lopt, opt->sopt);
			fbr_help(argv[0], EXIT_FAILURE);
		}
	}

	fbr_log_stderr = fbr_stderr_opt;
	fbr_dump_opts();
	
	if (fbr_listen.sa.sa_family == AF_INET
			&& fbr_listen.sin.sin_addr.s_addr == INADDR_ANY)
		FBR_WARN("listening on the IPv4 wildcard address\n");
	
	if (fbr_listen.sa.sa_family == AF_INET6) {
		
		int cmp;
		
		cmp = memcmp(fbr_listen.sin6.sin6_addr.s6_addr,
			     in6addr_any.s6_addr, sizeof in6addr_any.s6_addr);
		if (cmp == 0)
			FBR_WARN("listening on the IPv6 wildcard address\n");
	}
}


/*******************************************************************************
 * 
 * Start, stop & main loop
 * 
 ******************************************************************************/

static int fbr_listen_init(const union fbr_sockaddr *const addr)
{
	socklen_t addrlen;
	int fd;
	
	assert(addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
	
	if ((fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0)) < 0)
		FBR_FATAL("socket: %m\n");
	
	if (addr->sa.sa_family == AF_INET)
		addrlen = sizeof addr->sin;
	else
		addrlen = sizeof addr->sin6;
	
	if (bind(fd, &addr->sa, addrlen) < 0)
		FBR_FATAL("bind: %m\n");
	
	if (fbr_verbose) {
		char buf[INET6_ADDRSTRLEN];
		FBR_DEBUG("listening on %s/%" PRIu16 "\n",
			  fbr_format_sa(addr, buf),
			  ntohs(addr->sin6.sin6_port));
	}		
	
	return fd;
}

#if 0
static void fbr_listen_fini(const int fd)
{
	if (close(fd) < 0)
		FBR_FATAL("close: %m\n");
	
	FBR_DEBUG("listening socket closed\n");
}
#endif

static struct mnl_socket *fbr_mnl_init(void)
{
	struct mnl_socket *mnl;
	
	if ((mnl = mnl_socket_open(NETLINK_NETFILTER)) == NULL)
		FBR_FATAL("mnl_socket_open: %m\n");
	
	if (mnl_socket_bind(mnl, 0, MNL_SOCKET_AUTOPID) < 0)
		FBR_FATAL("mnl_socket_bind: %m\n");
	
	FBR_DEBUG("netfilter netlink socket created and bound\n");

	return mnl;
}

static void fbr_mnl_fini(struct mnl_socket *const mnl)
{
	if (mnl_socket_close(mnl) < 0)
		FBR_FATAL("mnl_socket_close: %m\n");
	
	FBR_DEBUG("netfilter netlink socket closed\n");
}

static void fbr_add_addr(struct mnl_socket *const mnl,
			 const struct fbr_addr *const addr)
{
	uint8_t msgbuf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *attr_data, *attr_addr;
	char infobuf[INET6_ADDRSTRLEN];
	const char *set_name;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	ssize_t ret;
	time_t seq;
	
	set_name = (addr->family == AF_INET) ? fbr_set4_name : fbr_set6_name;
	
	nlh = mnl_nlmsg_put_header(msgbuf);
	nlh->nlmsg_type = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = time(&seq);
	
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof *nfg);
	nfg->nfgen_family = addr->family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;
	
	mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
	mnl_attr_put(nlh, IPSET_ATTR_SETNAME, strlen(set_name) + 1, set_name);
	
	attr_data = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
	attr_addr = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);
	
	if (addr->family == AF_INET) {
		mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER,
			     sizeof addr->in, &addr->in);
		fbr_inet_ntop(AF_INET, &addr->in, infobuf);
	}
	else {
		mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER,
			     sizeof addr->in6, &addr->in6);
		fbr_inet_ntop(AF_INET6, &addr->in6, infobuf);
	}
	
	mnl_attr_nest_end(nlh, attr_addr);
	mnl_attr_nest_end(nlh, attr_data);
	
	if (mnl_socket_sendto(mnl, nlh, nlh->nlmsg_len) < 0) {
		FBR_ERR("mnl_socket_sendto: %m\n");
		exit(EXIT_FAILURE);
	}
	
	if ((ret = mnl_socket_recvfrom(mnl, msgbuf, sizeof msgbuf)) < 0) {
		FBR_ERR("mnl_socket_recvfrom: %m\n");
		exit(EXIT_FAILURE);
	}
	
	do {
		if ((ret = mnl_cb_run(msgbuf, ret, seq, 0, 0, 0)) < 0) {
			FBR_ERR("mnl_cb_run: %m\n");
			exit(EXIT_FAILURE);
		}
	}
	while (ret > 0);
	
	FBR_INFO("added %s to ipset %s\n", infobuf, set_name);
}

static volatile sig_atomic_t fbr_got_signal = 0;
static volatile int fbr_signhdlr_fd;

static void fbr_signal_hndlr(const int signum __attribute__((unused)))
{
	close(fbr_signhdlr_fd);
	fbr_got_signal = 1;
}

static void fbr_sighndlr_init(const int fd)
{
	fbr_signhdlr_fd = fd;

	if (signal(SIGTERM, fbr_signal_hndlr) == SIG_ERR)
		FBR_FATAL("signal: %m\n");
	if (signal(SIGINT, fbr_signal_hndlr) == SIG_ERR)
		FBR_FATAL("signal: %m\n");
}

int main(int argc __attribute__((unused)), const char *const *const argv)
{
	union fbr_sockaddr client;
	struct mnl_socket *mnl;
	struct fbr_addr inbuf;
	socklen_t clientsz;
	ssize_t insize;
	int listenfd;
	
	fbr_parse_opts(argv);
	listenfd = fbr_listen_init(&fbr_listen);
	mnl = fbr_mnl_init();
	fbr_sighndlr_init(listenfd);
	
	while (!fbr_got_signal) {
		
		clientsz = sizeof client;
		insize = recvfrom(listenfd, &inbuf, sizeof inbuf, 0, &client.sa,
				  &clientsz);
		if (insize < 0) {
			if (fbr_got_signal)
				break;
			FBR_FATAL("recvfrom: %m\n");
		}
		
		if (fbr_verbose) {
			char buf[INET6_ADDRSTRLEN];
			FBR_DEBUG("Received %zd bytes from %s/%" PRIu16 "\n",
				  insize, fbr_format_sa(&client, buf),
				  ntohs(client.sin.sin_port));
		}
		
		if (insize < sizeof inbuf) {
			FBR_WARN("received %zd bytes; expected %zd\n", insize,
				 sizeof inbuf);
			continue;
		}
		
		inbuf.family = ntohs(inbuf.family);
		
		if (inbuf.family != AF_INET && inbuf.family != AF_INET6) {
			FBR_WARN("received unknown address family: %d\n",
				 inbuf.family);
			continue;
		}
		
		fbr_add_addr(mnl, &inbuf);
	}
	
	fbr_mnl_fini(mnl);
	return EXIT_SUCCESS;
}
