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

#ifndef OPENFORTIVPN_DHCP_H
#define OPENFORTIVPN_DHCP_H

#include <sys/types.h>

#ifdef __clang__
/*
 * Get rid of Mac OS X 10.7 and greater deprecation warnings
 * see for instance https://wiki.openssl.org/index.php/Hostname_validation
 * this pragma selectively suppresses this type of warnings in clang
 */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

struct tunnel;

int start_dhcpd(struct tunnel *tunnel);

int stop_dhcpd(struct tunnel *tunnel);

#endif
