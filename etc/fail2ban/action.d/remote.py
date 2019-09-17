#
# Copyright 2019 Ian Pilcher <arequipeno@gmail.com>
#
# This program is free software.  You can redistribute it or modify it under
# the terms of version 2 of the GNU General Public License (GPL), as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY -- without even the implied warranty of MERCHANTIBILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the text of the GPL for more details.
#
# Version 2 of the GNU General Public License is available at:
#
#   http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#

import ipaddress
import socket

from socket import AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP

from fail2ban.server.actions import ActionBase

class RemoteAction(ActionBase):

	def __init__(self, jail, name, remote):
		super(RemoteAction, self).__init__(jail, name)
		self.remote = ipaddress.ip_address(remote)

	def start(self):
		self.socket = socket.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
		self.socket.bind(('', 789))

	def stop(self):
		self.socket.close()

	def ban(self, aInfo):
		ip = ipaddress.ip_address(unicode(aInfo['ip']))
		msg = bytearray(20)
		if ip.version == 4:
			msg[1] = AF_INET
			msg[4:8] = ip.packed
		else:
			msg[1] = AF_INET6
			msg[4:20] = ip.packed
		self.socket.sendto(msg, (str(self.remote), 789))

	def unban(self, aInfo):
		pass

Action = RemoteAction
