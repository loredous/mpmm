# Modern Packet Message Manager
# Copyright (C) 2023  Jeremy Banker

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
from logging import DEBUG, basicConfig, getLogger

from shared.kiss import KISSTCPClient
from shared.ax25 import AX25Client


if __name__ == "__main__":
    import signal

    def close():
        exit()

    basicConfig(level=DEBUG)
    logger = getLogger('KISSTest')
    logger.info('Starting KISS Test client')
    kiss_client = KISSTCPClient("192.168.0.13:8001")
    ax25_client = AX25Client(kiss_client, promiscuous=True)
    loop = asyncio.get_event_loop()
    loop.create_task(ax25_client.start())
    loop.add_signal_handler(signal.SIGINT, close)
    ax25_client.add_listener('W0IA-7')
    loop.run_forever()
