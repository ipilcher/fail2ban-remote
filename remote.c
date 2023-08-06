/*
 * Copyright 2019, 2022, 2023 Ian Pilcher <arequipeno@gmail.com>
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

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter.h>

#include <libmnl/libmnl.h>

#define FBR_MAX_TIMEOUT		31557600  /* 365.25 days */


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

struct fbr_set_opts {
	const char 	*table;
	const char 	*set;
	unsigned int	timeout;
	uint16_t	proto;
};

static struct fbr_set_opts fbr_set_opts4 = { .timeout = 3600 };
static struct fbr_set_opts fbr_set_opts6 = { .timeout = 3600 };
static _Bool fbr_stderr_opt;
static _Bool fbr_verbose;
static union fbr_sockaddr fbr_listen = {
	.sin6 = { .sin6_port = HTONS(789) }
};

__attribute__((noreturn))
static void fbr_help(const char *const exec, const int rc)
{
	printf("Usage: %s [-e|--stderr] [-v|--verbose] [-h|--help]\n"
			"\t[-l|--listen-port PORT] -a|--listen-addr ADDRESS\n"
			"\t-p|--ipv4-proto PROTOCOL -P|--ipv6-proto PROTOCOL\n"
			"\t-t|--ipv4-table TABLE -T|--ipv6-table TABLE\n"
			"\t-s|--ipv4-set SET -S|--ipv6-set SET\n"
			"\t[-o|--ipv4-timeout SECONDS] "
				"[-O|--ipv6_timeout SECONDS]\n",
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
	if (*arg == '\0' || strlen(arg) >= NFT_SET_MAXNAMELEN) {
		FBR_ERR("invalid IPv4 set name: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
	
	fbr_set_opts4.set = arg;
}

static void fbr_parse_set6(const char *const exec, const char *const arg)
{
	if (*arg == '\0' || strlen(arg) >= NFT_SET_MAXNAMELEN) {
		FBR_ERR("invalid IPv6 set name: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
	
	fbr_set_opts6.set = arg;
}

static void fbr_parse_table4(const char *const exec, const char *const arg)
{
	if (*arg == '\0' || strlen(arg) >= NFT_TABLE_MAXNAMELEN) {
		FBR_ERR("invalid IPv4 table name: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}

	fbr_set_opts4.table = arg;
}

static void fbr_parse_table6(const char *const exec, const char *const arg)
{
	if (*arg == '\0' || strlen(arg) >= NFT_TABLE_MAXNAMELEN) {
		FBR_ERR("invalid IPv6 table name: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}

	fbr_set_opts6.table = arg;
}

static void fbr_parse_proto4(const char *const exec, const char *const arg)
{
	if (strcmp(arg, "inet") == 0) {
		fbr_set_opts4.proto = NFPROTO_INET;
	}
	else if (strcmp(arg, "ip") == 0) {
		fbr_set_opts4.proto = NFPROTO_IPV4;
	}
	else if (strcmp(arg, "netdev") == 0) {
		fbr_set_opts4.proto = NFPROTO_NETDEV;
	}
	else {
		FBR_ERR("invalid IPv4 protocol "
				"(not 'inet', 'ip', or 'netdev'): %s\n",
			arg);
		fbr_help(exec, EXIT_FAILURE);
	}
}

static void fbr_parse_proto6(const char *const exec, const char *const arg)
{
	if (strcmp(arg, "inet") == 0) {
		fbr_set_opts6.proto = NFPROTO_INET;
	}
	else if (strcmp(arg, "ip6") == 0) {
		fbr_set_opts6.proto = NFPROTO_IPV6;
	}
	else if (strcmp(arg, "netdev") == 0) {
		fbr_set_opts6.proto = NFPROTO_NETDEV;
	}
	else {
		FBR_ERR("invalid IPv6 protocol "
				"(not 'inet', 'ip6', or 'netdev'): %s\n",
			arg);
		fbr_help(exec, EXIT_FAILURE);
	}
}

static void fbr_parse_port(const char *const exec, const char *const arg)
{
	unsigned long port;
	char *endptr;
	
	errno = 0;
	port = strtoul(arg, &endptr, 10);
	if (errno != 0 || *endptr != 0 || port > UINT16_MAX) {
		FBR_ERR("invalid listen port: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
		
	fbr_listen.sin6.sin6_port = htobe16(port);
}

static void fbr_parse_timeout4(const char *const exec, const char *const arg)
{
	char *endptr;

	errno = 0;
	fbr_set_opts4.timeout = strtoul(arg, &endptr, 10);
	if (errno != 0 || *endptr != 0
			|| fbr_set_opts4.timeout > FBR_MAX_TIMEOUT) {
		FBR_ERR("invalid IPv4 timeout: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
}

static void fbr_parse_timeout6(const char *const exec, const char *const arg)
{
	char *endptr;

	errno = 0;
	fbr_set_opts6.timeout = strtoul(arg, &endptr, 10);
	if (errno != 0 || *endptr != 0
			|| fbr_set_opts6.timeout > FBR_MAX_TIMEOUT) {
		FBR_ERR("invalid IPv6 timeout: %s\n", arg);
		fbr_help(exec, EXIT_FAILURE);
	}
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
	
	FBR_ERR("invalid listen address: %s\n", arg);
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
	{ "-e", "--stderr",		fbr_parse_stderr,	0, 0, 0 },
	{ "-v", "--verbose",		fbr_parse_verbose,	0, 0, 0 },
	{ "-h", "--help",		fbr_parse_help,		0, 0, 0 },
	{ "-l", "--listen-port",	fbr_parse_port,		1, 0, 0 },
	{ "-a", "--listen-addr",	fbr_parse_addr,		1, 0, 1 },
	{ "-p", "--ipv4-proto",		fbr_parse_proto4,	1, 0, 1 },
	{ "-P", "--ipv6-proto",		fbr_parse_proto6,	1, 0, 1 },
	{ "-t", "--ipv4-table",		fbr_parse_table4,	1, 0, 1 },
	{ "-T", "--ipv6-table",		fbr_parse_table6,	1, 0, 1 },
	{ "-s", "--ipv4-set",		fbr_parse_set4,		1, 0, 1 },
	{ "-S", "--ipv6-set",		fbr_parse_set6,		1, 0, 1 },
	{ "-o", "--ipv4-timeout",	fbr_parse_timeout4,	1, 0, 0 },
	{ "-O", "--ipv6-timeout",	fbr_parse_timeout6,	1, 0, 0 },
	{ NULL, NULL,			0,			0, 0, 0 }
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

static const char *fbr_fmt_proto(const uint16_t proto)
{
	switch (proto) {
		case NFPROTO_INET:	return "inet";
		case NFPROTO_IPV4:	return "ip";
		case NFPROTO_IPV6:	return "ip6";
		case NFPROTO_NETDEV:	return "netdev";
	}

	abort();
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
	FBR_DEBUG("  listen address: %s\n", fbr_format_sa(&fbr_listen, buf));
	FBR_DEBUG("  listen port: %" PRIu16 "\n",
		  be16toh(fbr_listen.sin.sin_port));

	FBR_DEBUG("  IPv4 protocol: %s\n", fbr_fmt_proto(fbr_set_opts4.proto));
	FBR_DEBUG("  IPv4 table: %s\n", fbr_set_opts4.table);
	FBR_DEBUG("  IPv4 set: %s\n", fbr_set_opts4.set);
	FBR_DEBUG("  IPv4 timeout: %u\n", fbr_set_opts4.timeout);

	FBR_DEBUG("  IPv6 protocol: %s\n", fbr_fmt_proto(fbr_set_opts6.proto));
	FBR_DEBUG("  IPv6 table: %s\n", fbr_set_opts6.table);
	FBR_DEBUG("  IPv6 set: %s\n", fbr_set_opts6.set);
	FBR_DEBUG("  IPv6 timeout: %u\n", fbr_set_opts6.timeout);
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

static struct mnl_socket *fbr_mnl_socket;
static unsigned int fbr_mnl_portid;
static uint32_t fbr_mnl_sequence;

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
			  be16toh(addr->sin6.sin6_port));
	}		
	
	return fd;
}

static void fbr_mnl_init(void)
{
	if ((fbr_mnl_socket = mnl_socket_open(NETLINK_NETFILTER)) == NULL)
		FBR_FATAL("mnl_socket_open: %m\n");
	
	if (mnl_socket_bind(fbr_mnl_socket, 0, MNL_SOCKET_AUTOPID) < 0)
		FBR_FATAL("mnl_socket_bind: %m\n");

	fbr_mnl_portid = mnl_socket_get_portid(fbr_mnl_socket);
	
	FBR_DEBUG("netfilter netlink socket created and bound\n");
}

static void fbr_mnl_fini(void)
{
	if (mnl_socket_close(fbr_mnl_socket) < 0)
		FBR_FATAL("mnl_socket_close: %m\n");
	
	FBR_DEBUG("netfilter netlink socket closed\n");
}

static void fbr_elem_msg(struct mnl_nlmsg_batch *const batch,
			 const uint16_t msg_type,
			 const struct fbr_addr *const addr,
			 const struct fbr_set_opts *set_opts,
			 const _Bool timeout)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	struct nlattr *elem_list_attr, *elem_attr, *key_attr;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | msg_type;
	nlh->nlmsg_seq = fbr_mnl_sequence++;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (msg_type == NFT_MSG_NEWSETELEM)
		nlh->nlmsg_flags |= NLM_F_CREATE;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof *nfg);
	nfg->nfgen_family = set_opts->proto;
	nfg->version=NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, set_opts->table);
	mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, set_opts->set);

	elem_list_attr = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
	elem_attr = mnl_attr_nest_start(nlh, 1);  /* nla_type is index # */

	if (timeout) {
		mnl_attr_put_u64(nlh, NFTA_SET_ELEM_TIMEOUT,
				 htobe64((uint64_t)set_opts->timeout * 1000));
	}

	key_attr = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_KEY);

	if (addr->family == AF_INET) {
		mnl_attr_put(nlh, NFTA_DATA_VALUE, sizeof addr->in, &addr->in);
	}
	else {
		mnl_attr_put(nlh, NFTA_DATA_VALUE,
			     sizeof addr->in6, &addr->in6);
	}

	mnl_attr_nest_end(nlh, key_attr);
	mnl_attr_nest_end(nlh, elem_attr);
	mnl_attr_nest_end(nlh, elem_list_attr);
}

static void fbr_batch_msg(struct mnl_nlmsg_batch *const batch,
			  const uint16_t msg_type)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_seq = fbr_mnl_sequence++;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof *nfg);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version=NFNETLINK_V0;
	nfg->res_id = htobe16(NFNL_SUBSYS_NFTABLES);
}

static void fbr_batch_next(struct mnl_nlmsg_batch *const batch)
{
	if (!mnl_nlmsg_batch_next(batch))
		FBR_FATAL("mnl_nlmsg_batch_next: %m\n");
}

static size_t fbr_build_batch(uint8_t *const buf,
			      const struct fbr_addr *const addr,
			      const struct fbr_set_opts *const set_opts)
{
	struct mnl_nlmsg_batch *batch;
	size_t len;

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL)
		FBR_FATAL("mnl_nlmsg_batch_start: %m\n");

	fbr_batch_msg(batch, NFNL_MSG_BATCH_BEGIN);
	fbr_batch_next(batch);
	fbr_elem_msg(batch, NFT_MSG_NEWSETELEM, addr, set_opts, 0);
	fbr_batch_next(batch);
	fbr_elem_msg(batch, NFT_MSG_DELSETELEM, addr, set_opts, 0);
	fbr_batch_next(batch);
	fbr_elem_msg(batch, NFT_MSG_NEWSETELEM, addr, set_opts, 1);
	fbr_batch_next(batch);
	fbr_batch_msg(batch, NFNL_MSG_BATCH_END);
	fbr_batch_next(batch);  /* Check that last message fit */

	len = mnl_nlmsg_batch_size(batch);
	mnl_nlmsg_batch_stop(batch);

	return len;
}

static void fbr_add_addr(const struct fbr_addr *const addr)
{
	uint8_t buf[MNL_SOCKET_BUFFER_SIZE * 2];
	char addrbuf[INET6_ADDRSTRLEN];
	const struct fbr_set_opts *set_opts;
	size_t len;
	ssize_t got;
	unsigned int i;
	uint32_t seq;

	if (addr->family == AF_INET) {
		set_opts = &fbr_set_opts4;
		fbr_inet_ntop(AF_INET, &addr->in, addrbuf);
	}
	else {
		set_opts = &fbr_set_opts6;
		fbr_inet_ntop(AF_INET6, &addr->in6, addrbuf);
	}

	seq = fbr_mnl_sequence + 1;

	len = fbr_build_batch(buf, addr, set_opts);

	if ((mnl_socket_sendto(fbr_mnl_socket, buf, len)) < 0)
		FBR_FATAL("mnl_socket_sendto: %m\n");

	for (i = 0; i < 3; ++i, ++seq) {

		got = mnl_socket_recvfrom(fbr_mnl_socket, buf, sizeof buf);
		if (got < 0)
			FBR_FATAL("mnl_socket_recvfrom: %m\n");

		if (mnl_cb_run(buf, got, seq, fbr_mnl_portid, NULL, NULL) < 0)
			FBR_FATAL("mnl_cb_run: %m\n");
	}

	FBR_INFO("added %s to %s:%s:%s\n", addrbuf,
		 fbr_fmt_proto(set_opts->proto),
		 set_opts->table, set_opts->set);
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
	struct fbr_addr inbuf;
	socklen_t clientsz;
	ssize_t insize;
	int listenfd;
	
	fbr_parse_opts(argv);
	listenfd = fbr_listen_init(&fbr_listen);
	fbr_mnl_init();
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
				  be16toh(client.sin.sin_port));
		}
		
		if ((size_t)insize < sizeof inbuf) {
			FBR_WARN("received %zd bytes; expected %zd\n", insize,
				 sizeof inbuf);
			continue;
		}
		
		inbuf.family = be16toh(inbuf.family);
		
		if (inbuf.family != AF_INET && inbuf.family != AF_INET6) {
			FBR_WARN("received unknown address family: %d\n",
				 inbuf.family);
			continue;
		}
		
		fbr_add_addr(&inbuf);
	}
	
	fbr_mnl_fini();
	return EXIT_SUCCESS;
}
