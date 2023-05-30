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
from logging import getLogger
from pydantic import BaseModel, validator

from typing import List, Self


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
        kiss_frame += type_indicator.to_bytes()

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
                kiss_frame += byte.to_bytes()

        # End the KISS frame with FEND
        kiss_frame += bytes([KISSCode.FEND.value])
        return kiss_frame

    @classmethod
    def decode(cls, data: bytes) -> List[Self]:
        """
        Decode raw bytes of one or more KISS frames into KISSFrame objects

        :param data: Raw Bytes representing a KISS frame

        :returns: List of KISSFrame objects decoded from bytes
        """
        frames = data.split(bytes([KISSCode.FEND.value]))
        decoded_frames = []
        for frame in frames:
            if frame == b"":
                continue
            decoded_type = frame[0]
            decoded_command = KISSCommand(decoded_type & 15)
            decoded_port = decoded_type & 240 >> 4

            decoded_data = []
            for byte in frame[1:]:
                match byte:
                    case KISSCode.FESC.value:
                        continue
                    case KISSCode.TFEND.value:
                        decoded_data.append(KISSCode.FEND.value)
                    case KISSCode.TFESC.value:
                        decoded_data.append(KISSCode.FESC.value)
                    case _:
                        decoded_data.append(byte)
            decoded_frames.append(
                cls(
                    data=bytes(decoded_data), command=decoded_command, port=decoded_port
                )
            )
        return decoded_frames


class KISSClient(ABC):
    def __init__(self, address: str, logger=None):
        if not logger:
            logger = getLogger(f"KISSClient[{address}]")
        self.logger = logger
        self.logger.debug(f"Setting up KISS Client for address {address}")
        self.address = address

    async def receive_callback(self, frame: bytes):
        self.logger.debug(f"Received: {frame}")

    async def decode_callback(self, frame: KISSFrame):
        self.logger.debug(f"Decoded: {frame.data}")

    async def start_listen(self):
        self.logger.debug("start_listen requested")
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
        raise RuntimeError(
            f"Stop was requested on KISSClient[{self.address}] but failed to stop with {timeout}s timeout."
        )

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
        address_parts = self.address.split(":")
        self.logger.debug(f"Opening TCP connection to {self.address}")
        self.reader, self.writer = await asyncio.open_connection(
            address_parts[0], address_parts[1]
        )

    async def listen_loop(self):
        while True:
            if not self.reader:
                self.logger.exception("listen_loop called without reader!")
                raise RuntimeError("Issue in listen loop: reader is None")
            try:
                async with asyncio.timeout(10):
                    data = await self.reader.read(32768)
                    if data:
                        self.base_loop.create_task(self.receive_callback(data))
                        frames = KISSFrame.decode(data)
                        for frame in frames:
                            self.logger.debug(f"Sending callback for [{frame}]")
                            self.base_loop.create_task(self.decode_callback(frame))
            except TimeoutError:
                pass
            if self._stop_requested:
                self._running = False
                return
            await asyncio.sleep(0.1)

    async def send(self, frame: KISSFrame):
        self.logger.debug(f"Send requested for frame [{frame}]")
        if not self.writer:
            self.logger.exception("send called without writer!")
            raise RuntimeError("Issue in send: writer is None")
        self.writer.write(frame.encode())

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


if __name__ == "__main__":
    test = KISSFrame.decode(
        b'\xc0\x00\xa6\xb0j\xa2\xac\xa8`\x9c`\x82\x9a\xb2@\xe8\xae\x82l\x92\x8c\x92\xf8\x9c`\x82\xaa\xb0@\xe2\xae\x92\x88\x8ad@\xe1\x03\xf0`pL}l!vv/`"HJ}_%\r\xc0'
    )
    pass
