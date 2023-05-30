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

from shared.kiss import KISSFrame, KISSTCPClient
from shared.ax25 import AX25Frame


if __name__ == "__main__":
    import signal

    async def delay(coro, seconds):
        await asyncio.sleep(30)
        await coro

    def close():
        print("Got Ctrl-C!")
        exit()

    async def local_recieve_callback(frame: bytes):
        with open("kiss_data", "a") as datafile:
            datafile.write(frame.hex())
            datafile.write("\n")

    async def local_callback(frame: KISSFrame):
        aframe = AX25Frame.decode(frame)
        with open("ax25_data", "a") as datafile:
            datafile.write(aframe.json())
            datafile.write("\n")
        print(aframe)

    basicConfig(level=DEBUG)
    logger = getLogger("KISSTest")
    logger.info("Starting KISS Test client")
    client = KISSTCPClient("192.168.0.13:8001")
    client.decode_callback = local_callback
    client.receive_callback = local_recieve_callback
    loop = asyncio.get_event_loop()
    loop.create_task(client.start_listen())
    loop.add_signal_handler(signal.SIGINT, close)
    loop.run_forever()
