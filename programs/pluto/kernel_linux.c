/*
 * routines that are Linux specific
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2005-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_addr.h>


#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_nokernel.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"
#include "ip_address.h"
#include "ip_info.h"

#ifdef HAVE_BROKEN_POPEN
/*
 * including this may be acceptable on a system without a working popen
 * but a normal system should not need this, <errno.h> should cover it ;-)
 */
#include <asm-generic/errno.h>
#endif

/* invoke the updown script to do the routing and firewall commands required
 *
 * The user-specified updown script is run.  Parameters are fed to it in
 * the form of environment variables.  All such environment variables
 * have names starting with "PLUTO_".
 *
 * The operation to be performed is specified by PLUTO_VERB.  This
 * verb has a suffix "-host" if the client on this end is just the
 * host; otherwise the suffix is "-client".  If the address family
 * of the host is IPv6, an extra suffix of "-v6" is added.
 *
 * "prepare-host" and "prepare-client" are used to delete a route
 * that may exist (due to forces outside of Pluto).  It is used to
 * prepare for pluto creating a route.
 *
 * "route-host" and "route-client" are used to install a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "unroute-host" and "unroute-client" are used to delete a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "up-host" and "up-client" are run when an eroute is added (not replaced).
 * They are useful for adjusting a firewall: usually for adding a rule
 * to let processed packets flow between clients.  Note that only
 * one eroute may exist for a pair of client subnets but inbound
 * IPsec SAs may persist without an eroute.
 *
 * "down-host" and "down-client" are run when an eroute is deleted.
 * They are useful for adjusting a firewall.
 */

static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

struct raw_iface *find_raw_ifaces4(void)
{
	int j;	/* index into buf */
	struct ifconf ifconf;
	struct ifreq *buf = NULL;	/* for list of interfaces -- arbitrary limit */
	struct raw_iface *rifaces = NULL;
	int master_sock = safe_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);        /* Get a UDP socket */
	static const int on = TRUE;     /* by-reference parameter; constant, we hope */

	/*
	 * Current upper bound on number of interfaces.
	 * Tricky: because this is a static, we won't have to start from
	 * 64 in subsequent calls.
	 */
	static int num = 64;

	/* get list of interfaces with assigned IPv4 addresses from system */

	if (master_sock == -1)
		EXIT_LOG_ERRNO(errno, "socket() failed in find_raw_ifaces4()");

	/*
	 * Without SO_REUSEADDR, bind() of master_sock will cause
	 * 'address already in use?
	 */
	if (setsockopt(master_sock, SOL_SOCKET, SO_REUSEADDR,
			(const void *)&on, sizeof(on)) < 0)
		EXIT_LOG_ERRNO(errno, "setsockopt(SO_REUSEADDR) in find_raw_ifaces4()");

	/* bind the socket */
	{
		ip_address any = address_any(&ipv4_info);
		ip_endpoint any_ep = endpoint(&any, pluto_port);
		ip_sockaddr any_sa;
		size_t any_sa_size = endpoint_to_sockaddr(&any_ep, &any_sa);
		if (bind(master_sock, &any_sa.sa, any_sa_size) < 0)
			EXIT_LOG_ERRNO(errno, "bind() failed in %s()", __func__);
	}

	/* a million interfaces is probably the maximum, ever... */
	for (; num < (1024 * 1024); num *= 2) {
		/* Get num local interfaces.  See netdevice(7). */
		ifconf.ifc_len = num * sizeof(struct ifreq);

		struct ifreq *tmpbuf = realloc(buf, ifconf.ifc_len);

		if (tmpbuf == NULL) {
			free(buf);
			EXIT_LOG_ERRNO(errno,
				       "realloc of %d in find_raw_ifaces4()",
				       ifconf.ifc_len);
		}
		buf = tmpbuf;
		memset(buf, 0xDF, ifconf.ifc_len);	/* stomp */
		ifconf.ifc_buf = (void *) buf;

		if (ioctl(master_sock, SIOCGIFCONF, &ifconf) == -1)
			EXIT_LOG_ERRNO(errno,
				       "ioctl(SIOCGIFCONF) in find_raw_ifaces4()");

		/* if we got back less than we asked for, we have them all */
		if (ifconf.ifc_len < (int)(sizeof(struct ifreq) * num))
			break;
	}

	/* Add an entry to rifaces for each interesting interface. */
	for (j = 0; (j + 1) * sizeof(struct ifreq) <= (size_t)ifconf.ifc_len;
	     j++) {
		struct raw_iface ri;
		const struct sockaddr_in *rs =
			(struct sockaddr_in *) &buf[j].ifr_addr;
		struct ifreq auxinfo;

		/* build a NUL-terminated copy of the rname field */
		memcpy(ri.name, buf[j].ifr_name, IFNAMSIZ-1);
		ri.name[IFNAMSIZ-1] = '\0';
		DBG(DBG_CONTROLMORE,
		    DBG_log("Inspecting interface %s ", ri.name));

		/* ignore all but AF_INET interfaces */
		if (rs->sin_family != AF_INET) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignoring non AF_INET interface %s ",
				    ri.name));
			continue; /* not interesting */
		}

		/* ignore if our interface names were specified, and this isn't one - for KLIPS/MAST only */
		if (pluto_ifn_roof != 0 &&
		    kern_interface == USE_KLIPS) {
			int i;

			DBG(DBG_CONTROLMORE,
			    DBG_log("interfaces= specified, applying filter"));

			for (i = 0; i != pluto_ifn_roof; i++)
				if (streq(ri.name, pluto_ifn[i])) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("interface name '%s' found in interfaces= line",
						    ri.name));
					break;
				}

			if (i == pluto_ifn_roof) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("interface name '%s' not present in interfaces= line - skipped",
					    ri.name));
				continue; /* not found -- skip */
			}
		}
		/* Find out stuff about this interface.  See netdevice(7). */
		zero(&auxinfo); /* paranoia */
		memcpy(auxinfo.ifr_name, buf[j].ifr_name, IFNAMSIZ-1);
		/* auxinfo.ifr_name[IFNAMSIZ-1] already '\0' */
		if (ioctl(master_sock, SIOCGIFFLAGS, &auxinfo) == -1) {
			LOG_ERRNO(errno,
				       "Ignored interface %s - ioctl(SIOCGIFFLAGS) failed in find_raw_ifaces4()",
				       ri.name);
			continue; /* happens when using device with label? */
		}
		if (!(auxinfo.ifr_flags & IFF_UP)) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignored interface %s - it is not up",
				    ri.name));
			continue; /* ignore an interface that isn't UP */
		}
		if (auxinfo.ifr_flags & IFF_SLAVE) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignored interface %s - it is a slave interface",
				    ri.name));
			continue; /* ignore slave interfaces; they share IPs with their master */
		}

		/* ignore unconfigured interfaces */
		if (rs->sin_addr.s_addr == 0) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignored interface %s - it is unconfigured",
				    ri.name));
			continue;
		}

		ri.addr = address_from_in_addr(&rs->sin_addr);
		ipstr_buf b;
		dbg("found %s with address %s", ri.name, ipstr(&ri.addr, &b));
		ri.next = rifaces;
		rifaces = clone_thing(ri, "struct raw_iface");
	}

	free(buf);	/* was allocated via realloc() */
	close(master_sock);
	return rifaces;
}

static int cmp_iface(const void *lv, const void *rv)
{
	const struct raw_iface *const *ll = lv;
	const struct raw_iface *const *rr = rv;
	const struct raw_iface *l = *ll;
	const struct raw_iface *r = *rr;
	/* return l - r */
	int i;
	/* protocol */
	i = addrtypeof(&l->addr) - addrtypeof(&r->addr);
	if (i != 0) {
		return i;
	}
	/* loopback=0 < addr=1 < any=2 < ??? */
#define SCORE(I) (isloopbackaddr(&I->addr) ? 0				\
		  : isanyaddr(&I->addr) ? 2				\
		  : 1)
	i = SCORE(l) - SCORE(r);
	if (i != 0) {
		return i;
	}
#undef SCORE
	/* name */
	i = strcmp(l->name, r->name);
	if (i != 0) {
		return i;
	}
	/*
	 * address
	 */
	i = addrcmp(&l->addr, &r->addr);
	if (i != 0) {
		return i;
	}
	/* port */
	i = hportof(&l->addr) - hportof(&r->addr);
	if (i != 0) {
		return i;
	}
	/* what else */
	dbg("interface sort not stable or duplicate");
	return 0;
}

static void sort_ifaces(struct raw_iface **rifaces)
{
	/* how many? */
	unsigned nr_ifaces = 0;
	for (struct raw_iface *i = *rifaces; i != NULL; i = i->next) {
		nr_ifaces++;
	}
	if (nr_ifaces == 0) {
		dbg("no interfaces to sort");
		return;
	}
	/* turn the list into an array */
	struct raw_iface **ifaces = alloc_things(struct raw_iface *, nr_ifaces,
						 "ifaces for sorting");
	ifaces[0] = *rifaces;
	for (unsigned i = 1; i < nr_ifaces; i++) {
		ifaces[i] = ifaces[i-1]->next;
	}
	/* sort */
	dbg("sorting %u interfaces", nr_ifaces);
	qsort(ifaces, nr_ifaces, sizeof(ifaces[0]), cmp_iface);
	/* turn the array back into a list */
	for (unsigned i = 0; i < nr_ifaces - 1; i++) {
		ifaces[i]->next = ifaces[i+1];
	}
	ifaces[nr_ifaces-1]->next = NULL;
	/* clean up and return */
	*rifaces = ifaces[0];
	pfree(ifaces);
}

struct raw_iface *find_raw_ifaces6(void)
{
	/* Get list of interfaces with IPv6 addresses from system from /proc/net/if_inet6).
	 *
	 * Documentation of format?
	 * RTFS: linux-2.2.16/net/ipv6/addrconf.c:iface_proc_info()
	 *       linux-2.4.9-13/net/ipv6/addrconf.c:iface_proc_info()
	 *
	 * Sample from Gerhard's laptop:
	 *	00000000000000000000000000000001 01 80 10 80       lo
	 *	30490009000000000000000000010002 02 40 00 80   ipsec0
	 *	30490009000000000000000000010002 07 40 00 80     eth0
	 *	fe80000000000000025004fffefd5484 02 0a 20 80   ipsec0
	 *	fe80000000000000025004fffefd5484 07 0a 20 80     eth0
	 *
	 * Each line contains:
	 * - IPv6 address: 16 bytes, in hex, no punctuation
	 * - ifindex: 1-4 bytes, in hex
	 * - prefix_len: 1 byte, in hex
	 * - scope (e.g. global, link local): 1 byte, in hex
	 * - flags: 1 byte, in hex
	 * - device name: string, followed by '\n'
	 */
	struct raw_iface *rifaces = NULL;
	static const char proc_name[] = "/proc/net/if_inet6";
	FILE *proc_sock = fopen(proc_name, "r");

	if (proc_sock == NULL) {
		DBG(DBG_CONTROL, DBG_log("could not open %s", proc_name));
	} else {
		for (;; ) {
			struct raw_iface ri;
			unsigned short xb[8];           /* IPv6 address as 8 16-bit chunks */
			char sb[8 * 5];                 /* IPv6 address as string-with-colons */
			unsigned int if_idx;            /* proc field, not used */
			unsigned int plen;              /* proc field, not used */
			unsigned int scope;             /* proc field, used to exclude link-local */
			unsigned int dad_status;        /* proc field */
			/* ??? I hate and distrust scanf -- DHR */
			int r = fscanf(proc_sock,
				       "%4hx%4hx%4hx%4hx%4hx%4hx%4hx%4hx"
				       " %x %02x %02x %02x %20s\n",
				       xb + 0, xb + 1, xb + 2, xb + 3, xb + 4,
				       xb + 5, xb + 6, xb + 7,
				       &if_idx, &plen, &scope, &dad_status,
				       ri.name);

			/* ??? we should diagnose any problems */
			if (r != 13)
				break;

			/* ignore addresses with link local scope.
			 * From linux-2.4.9-13/include/net/ipv6.h:
			 * IPV6_ADDR_LINKLOCAL	0x0020U
			 * IPV6_ADDR_SCOPE_MASK	0x00f0U
			 */
			if ((scope & 0x00f0U) == 0x0020U)
				continue;

			if (dad_status & (IFA_F_TENTATIVE
#ifdef IFA_F_DADFAILED
						| IFA_F_DADFAILED
#endif
				))
				continue;

			snprintf(sb, sizeof(sb),
				 "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				 xb[0], xb[1], xb[2], xb[3], xb[4], xb[5],
				 xb[6], xb[7]);

			happy(ttoaddr_num(sb, 0, AF_INET6, &ri.addr));

			if (address_is_specified(&ri.addr)) {
				dbg("found %s with address %s",
				    ri.name, sb);
				ri.next = rifaces;
				rifaces = clone_thing(ri, "struct raw_iface");
			}
		}
		fclose(proc_sock);
		/*
		 * Sort the list by IPv6 address in assending order.
		 *
		 * XXX: The code then inserts these interfaces in
		 * _reverse_ order (why I don't know) - the loop-back
		 * interface ends up last.  Should the insert code
		 * (scattered between kernel_*.c files) instead
		 * maintain the "interfaces" structure?
		 */
		sort_ifaces(&rifaces);
	}

	return rifaces;
}

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */
bool use_interface(const char *rifn)
{
	if (pluto_ifn_roof >= (int)elemsof(pluto_ifn)) {
		return FALSE;
	} else {
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return TRUE;
	}
}

