/*
 *  Copyright (c) 2015 Adrien Verg├®
 *  Copyright (c) 2024 Vuhuy Luu
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dhcp.h"
#include "log.h"
#include "tunnel.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

static unsigned char* get_if_addr_octet(struct tunnel *tunnel)
{
	struct ifaddrs *ifaddr, *ifa;
	static unsigned char ip_octets[4];

	if (getifaddrs(&ifaddr) == -1) {
		log_debug("%s: cannot fetch IP addresses\n", __func__);
		return NULL;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL
			|| ifa->ifa_addr->sa_family != AF_INET
			|| strcmp(ifa->ifa_name, tunnel->config->dhcpd_ifname) != 0)
			continue;

		struct sockaddr_in *ipv4 = (struct sockaddr_in *)ifa->ifa_addr;
		memcpy(ip_octets, &ipv4->sin_addr, 4);

		freeifaddrs(ifaddr);
		return ip_octets;
	}

	log_debug("%s: cannot find interface '%s'\n", __func__, tunnel->config->dhcpd_ifname);
	freeifaddrs(ifaddr);
	return NULL;
}

static char *format_route(struct rtentry *route, unsigned char *if_addr)
{
	int prefix_length = 0;
	unsigned char *mask =
		(unsigned char *)&((struct sockaddr_in *)&route->rt_genmask)->sin_addr.s_addr;

	for (int i = 0; i < 4; i++) {
		unsigned char byte = mask[i];

		while (byte) {
			prefix_length += byte & 1;
			byte >>= 1;
		}
	}

	static char output[60];
	unsigned char *dst =
		(unsigned char *)&((struct sockaddr_in *)&route->rt_dst)->sin_addr.s_addr;

	if (prefix_length > 24) {
		snprintf(output, sizeof(output), "%u, %u, %u, %u, %u, %u, %u, %u, %u",
			prefix_length, dst[0], dst[1], dst[2], dst[3],
			if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
	}
	else if (prefix_length > 16) {
		snprintf(output, sizeof(output), "%u, %u, %u, %u, %u, %u, %u, %u",
			prefix_length, dst[0], dst[1], dst[2],
			if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
	}
	else if (prefix_length >= 8) {
		snprintf(output, sizeof(output), "%u, %u, %u, %u, %u, %u, %u",
			prefix_length, dst[0], dst[1],
			if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
	}
	else {
		snprintf(output, sizeof(output), "%u, %u, %u, %u, %u, %u",
			prefix_length, dst[0],
			if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
	}

	log_debug("%s: pushing route %u.%u.%u.%u/%u to %u.%u.%u.%u\n",
		__func__, dst[0], dst[1], dst[2], dst[3], prefix_length,
		if_addr[0], if_addr[1], if_addr[2], if_addr[3]);

	return output;
}

static void write_dns(FILE *file, struct tunnel *tunnel)
{
	if (tunnel->ipv4.ns1_addr.s_addr != 0) {
		char ns1[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &tunnel->ipv4.ns1_addr, ns1, INET_ADDRSTRLEN);
		fprintf(file, "  option domain-name-servers");
		fprintf(file, " %s", ns1);
		log_debug("%s: using '%s' as primary nameserver\n", __func__, ns1);

		if (tunnel->ipv4.ns2_addr.s_addr != 0) {
			char ns2[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &tunnel->ipv4.ns2_addr, ns2, INET_ADDRSTRLEN);
			fprintf(file, ", %s", ns2);
			log_debug("%s: using '%s' as secondary nameserver\n", __func__, ns2);
		}

		fprintf(file, ";\n");
	}

	if (tunnel->ipv4.dns_suffix) {
		fprintf(file, "  option domain-search \"%s\";\n", tunnel->ipv4.dns_suffix);
		log_debug("%s: using '%s' as search domain\n", __func__, tunnel->ipv4.dns_suffix);
	}
}

static void write_routes(FILE *file, struct tunnel *tunnel, unsigned char *if_addr)
{
	if (tunnel->ipv4.split_routes) {
		int first = 1;
		for (int i = 0; i < tunnel->ipv4.split_routes; i++) {
			struct rtentry *route;
			route = &tunnel->ipv4.split_rt[i];

			if (route_dest(route).s_addr == route_dest(&tunnel->ipv4.gtw_rt).s_addr)
				continue;

			if (first) {
				fprintf(file, "  option rfc3442-classless-static-routes %s",
					format_route(route, if_addr));
				first = 0;
			}
			else {
				fprintf(file, ",\n                                         %s",
					format_route(route, if_addr));
			}
		}

		if (!first) {
			fprintf(file, ";\n");

			first = 1;
			for (int i = 0; i < tunnel->ipv4.split_routes; i++) {
				struct rtentry *route;
				route = &tunnel->ipv4.split_rt[i];

				if (route_dest(route).s_addr ==
					route_dest(&tunnel->ipv4.gtw_rt).s_addr)
					continue;

				if (first) {
					fprintf(file, "  option ms-classless-static-routes %s",
						format_route(route, if_addr));
					first = 0;
				}
				else {
					fprintf(file, ",\n                                    %s",
						format_route(route, if_addr));
				}
			}

			fprintf(file, ";\n");
		}
	}
	else {
		fprintf(file, "  option routers %u.%u.%u.%u;\n",
			if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
		log_debug("%s: set %u.%u.%u.%u as router",
			__func__, if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
	}
}

static int write_dhcpd_config(struct tunnel *tunnel)
{
	const char *filename = "/etc/dhcp/dhcpd.conf";
	FILE *file = fopen(filename, "w");

	if (!file) {
		log_debug("%s: failed to access dhcpd.conf\n", __func__);
		return -1;
	}

	unsigned char *if_addr = get_if_addr_octet(tunnel);

	if (if_addr == NULL) {
		fclose(file);
		return -1;
	}

	log_debug("%s: using network %u.%u.%u.%u/24\n",
		__func__, if_addr[0], if_addr[1], if_addr[2], if_addr[3]);
	log_debug("%s: writing dhcpd config\n", __func__);

	fprintf(file,
		"option rfc3442-classless-static-routes code 121 = array of integer 8;\n"
		"option ms-classless-static-routes code 249 = array of integer 8;\n\n"
		"subnet %u.%u.%u.0 netmask 255.255.255.0 {\n"
		"  range %u.%u.%u.100 %u.%u.%u.200;\n",
		if_addr[0], if_addr[1], if_addr[2],
		if_addr[0], if_addr[1], if_addr[2],
		if_addr[0], if_addr[1], if_addr[2]);

	if (tunnel->config->set_dns)
		write_dns(file, tunnel);

	if (tunnel->config->set_routes)
		write_routes(file, tunnel, if_addr);

	fprintf(file, "}\n");
	fclose(file);
	return 0;
}

/*
 * Start dhcpd by calling rc-service.
 */
int start_dhcpd(struct tunnel *tunnel)
{
	if (write_dhcpd_config(tunnel) != 0) {
		log_error("%s: cannot write dhcpd.conf\n",  __func__);
		return -1;
	}

	char if_command[IF_NAMESIZE + 12];
	snprintf(if_command, sizeof(if_command), "ifconfig %s up", tunnel->config->dhcpd_ifname);

	if (system(if_command) != 0) {
		log_error("%s: %s up failed\n", __func__, tunnel->config->dhcpd_ifname);
		return -1;
	}

	if (system("rc-service dhcpd restart") != 0) {
		log_error("%s: failed to (re)start the dhcpd service\n", __func__);
		return -1;
	}

	return 0;
}

/*
 * Stop dhcpd by calling tc-service.
 */
int stop_dhcpd(struct tunnel *tunnel)
{
	if (system("rc-service dhcpd stop") != 0) {
		log_error("%s: failed to stop dhcpd service\n", __func__);
		return -1;
	}

	char if_command[IF_NAMESIZE + 14];
	snprintf(if_command, sizeof(if_command), "ifconfig %s down", tunnel->config->dhcpd_ifname);

	if (system(if_command) != 0) {
		log_error("%s: %s down failed\n", __func__, tunnel->config->dhcpd_ifname);
		return -1;
	}

	return 0;
}
