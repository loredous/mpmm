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

from shared.kiss import KISSMockClient
from shared.ax25 import AX25Client, AX25Controller, AX25Listener


if __name__ == "__main__":
    import signal

    def close():
        controller.stop()
        exit()

    def handle_connection(connection):
        logger.info(f"Got callback for connection {connection}")

    async def pinger():
        while True:
            await asyncio.sleep(10)
            controller.send_ui_frame(
                "K0JLB-1", "ID", "Hello HRV!", client=controller.clients[0]
            )

    def got_ui(frame, client, port):
        logger.info(f'Got UI Frame: {frame}')

    basicConfig(level=DEBUG)
    logger = getLogger("KISSTest")
    logger.info("Starting KISS Test client")
    controller = AX25Controller()
    controller.start()
    kiss_client = KISSMockClient(loopback=True)
    controller.add_client(AX25Client(kiss_client))
    controller.add_ui_callback(got_ui)
    # controller.add_listener(
    #     AX25Listener(callsign="K0JLB-14", incoming_callback=handle_connection)
    # )
    loop = asyncio.get_event_loop()

    loop.create_task(pinger())
    #loop.add_signal_handler(sig=signal.SIGINT, callback=close)
    loop.run_forever()
