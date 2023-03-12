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

from abc import ABC, abstractmethod
import asyncio
from enum import Enum
from logging import getLogger, basicConfig, DEBUG
from pydantic import BaseModel, validator

from typing import Self


class KISSCommand(Enum):
    DATA_FRAME = 0
    TX_DELAY = 1
    PERSISTENCE = 2
    SLOT_TIME = 3
    TX_TAIL = 4
    FULL_DUPLEX = 5
    SET_HARDWARE = 6
    RETURN = 255


class KISSCode(Enum):
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD


class KISSFrame(BaseModel):
    data: bytes
    command: KISSCommand
    port: int

    @validator("port")
    def is_valid_port(cls, v):
        if v < 0 or v > 16:
            return ValueError("KISS port number must be between 0 and 16 inclusive")
        return v

    def encode(self) -> bytes:
        """
        Get the byte representation of the KISSFrame

        :returns: raw bytes representing the KISS frame
        """
        # KISS frame starts with FEND
        kiss_frame = bytes([KISSCode.FEND.value])

        # Add the command and port
        type_indicator = self.command.value | self.port << 4
        kiss_frame += bytes([type_indicator])

        # Encode each byte of the frame
        for byte in self.data:
            # If the byte is a KISS Frame End code, escape it
            if byte == KISSCode.FEND.value:
                kiss_frame += bytes([KISSCode.FESC.value, KISSCode.TFEND.value])
            # If the byte is a KISS Frame Escape code, escape it
            elif byte == KISSCode.FESC.value:
                kiss_frame += bytes([KISSCode.FESC.value, KISSCode.TFESC.value])
            # Otherwise, just add the byte to the KISS frame
            else:
                kiss_frame += bytes([byte])

        # End the KISS frame with FEND
        kiss_frame += bytes([KISSCode.FEND.value])
        return kiss_frame

    @classmethod
    def decode(cls, kiss_frame: bytes) -> Self:
        """
        Decode raw bytes of a KISS frame into a KISSFrame object

        :param kiss_frame: Raw Bytes representing a KISS frame

        :returns: KISSFrame object decoded from bytes
        :raises ValueError: bytes are not a valid KISS frame
        """
        if (
            kiss_frame[0] != KISSCode.FEND.value or kiss_frame[-1] != KISSCode.FEND.value
        ):
            raise ValueError(
                "provided kiss_frame is not a valid KISS frame. Does not begin and end with FEND (0xC0)"
            )
        if KISSCode.FEND.value in kiss_frame[2:-2]:
            raise ValueError(
                "provided kiss_frame is not a valid KISS frame, or may be multiple frames. Found FEND (0xC0) in data section of frame"
            )

        decoded_type = kiss_frame[1]
        decoded_command = KISSCommand(decoded_type & 15)
        decoded_port = decoded_type & 240 >> 4

        decoded_data = []
        for byte in kiss_frame[2:-1]:
            match byte:
                case KISSCode.FESC.value:
                    continue
                case KISSCode.TFEND.value:
                    decoded_data.append(KISSCode.FEND.value)
                case KISSCode.TFESC.value:
                    decoded_data.append(KISSCode.FESC.value)
                case _:
                    decoded_data.append(byte)

        return cls(data=bytes(decoded_data), command=decoded_command, port=decoded_port)


class KISSClient(ABC):

    def __init__(self, address: str, logger=None):
        if not logger:
            logger = getLogger(f'KISSClient[{address}]')
        self.logger = logger
        self.logger.debug(f'Setting up KISS Client for address {address}')
        self.address = address

    async def recieve_callback(self, frame: KISSFrame):
        self.logger.info(f'Recieved: {frame.data}')

    async def start_listen(self):
        self.logger.debug('start_listen requested')
        await self.setup()
        self.base_loop = asyncio.get_running_loop()
        self._stop_requested = False
        self._running = True
        self.base_loop.create_task(self.listen_loop())

    async def stop_listen(self, close=True, timeout: int = 60):
        self._stop_requested = True
        await self._await_stop(timeout)
        if close:
            self.close()

    async def _await_stop(self, timeout: int):
        for _ in range(timeout):
            if not self._running:
                return
            await asyncio.sleep(1)
        raise RuntimeError(f'Stop was requested on KISSClient[{self.address}] but failed to stop with {timeout}s timeout.')

    @abstractmethod
    async def listen_loop(self):
        pass

    @abstractmethod
    async def setup(self):
        pass

    @abstractmethod
    async def close(self):
        pass

    @abstractmethod
    async def send(self, frame: KISSFrame):
        pass


class KISSTCPClient(KISSClient):
    async def setup(self):
        address_parts = self.address.split(':')
        self.logger.debug(f'Opening TCP connection to {self.address}')
        self.reader, self.writer = await asyncio.open_connection(address_parts[0], address_parts[1])

    async def listen_loop(self):
        while True:
            if not self.reader:
                self.logger.exception('listen_loop called without reader!')
                raise RuntimeError('Issue in listen loop: reader is None')
            try:
                async with asyncio.timeout(10):
                    data = await self.reader.read(1024)
                    if data:
                        frame = KISSFrame.decode(data)
                        self.base_loop.create_task(self.recieve_callback(frame))
            except TimeoutError:
                pass
            if self._stop_requested:
                self._running = False
                return
            await asyncio.sleep(1)

    async def send(self, frame: KISSFrame):
        self.logger.debug(f'Send requested for frame [{frame}]')
        if not self.writer:
            self.logger.exception('send called without writer!')
            raise RuntimeError('Issue in send: writer is None')
        self.writer.write(frame.encode())
        self.writer.write_eof()

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


if __name__ == "__main__":
    import signal

    async def delay(coro, seconds):
        await asyncio.sleep(30)
        await coro

    def close():
        print('Got Ctrl-C!')
        exit()

    async def local_callback(frame: KISSFrame):
        print('Am in local callback!')
        print(frame)

    basicConfig(level=DEBUG)
    logger = getLogger('KISSTest')
    logger.info('Starting KISS Test client')
    client = KISSTCPClient("192.168.0.13:8001")
    client.recieve_callback = local_callback
    loop = asyncio.get_event_loop()
    loop.create_task(client.start_listen())
    loop.add_signal_handler(signal.SIGINT, close)
    # fr = KISSFrame(data=b'\x82\xa0\x9a\x92`h`\x96\x96`\xb0@@t\x9c`\x82\xaa\xb0@\xe2\xae\x92\x88\x8ad@c\x03\xf0@121504z3934.15N/10455.05W-WX3in1Mini U=12.4V.', command=KISSCommand.DATA_FRAME, port=0)
    # loop.create_task(delay(client.send(fr), 30))
    loop.run_forever()
