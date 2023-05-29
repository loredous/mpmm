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

from enum import Enum, Flag
from hashlib import sha1
from typing import List, Optional, Self, Tuple, Union
from queue import Queue, Empty
from logging import getLogger
import asyncio

from pydantic import BaseModel
from shared.utils import chunk
from shared.kiss import KISSCommand, KISSFrame, KISSClient


class AX25PID(Enum):
    NONE = 0x00
    ISO_8208 = 0x01
    TCP_COMPRESSED = 0x06
    TCP_UNCOMPRESSED = 0x07
    FRAGMENT = 0x08
    TEXNET = 0xC3
    LQP = 0xC4
    APPLETALK = 0xCA
    APPLETALK_ARP = 0xCB
    ARPA_IP = 0xCC
    ARPA_ADDR = 0xCD
    FLEXNET = 0xCE
    NETROM = 0xCF
    NO_LAYER_3 = 0xF0
    ESCAPE = 0xFF


class AX25Address(BaseModel):
    callsign: str
    ssid: str
    reserved_bit_5: bool = True
    reserved_bit_6: bool = True
    command_repeat_bit: bool

    @classmethod
    def decode(cls, address_bytes: bytes) -> Self:
        address = []
        for byte in address_bytes:
            address.append(byte >> 1)
        callsign = bytes(address[0:6]).decode().strip()
        ssid = int((address_bytes[6] & 30) >> 1)
        rb5 = bool((address_bytes[6] & 32))
        rb6 = bool((address_bytes[6] & 64))
        crb = bool((address_bytes[6] & 128))
        return cls(
            callsign=callsign,
            ssid=ssid,
            reserved_bit_5=rb5,
            reserved_bit_6=rb6,
            command_repeat_bit=crb
        )

    def encode(self):
        address_bytes = []
        address_bytes += self.callsign.encode('utf-8')
        address_bytes += [32] * (6 - len(address_bytes))  # Pad with spaces!
        for index in range(0, len(address_bytes)):
            address_bytes[index] = (address_bytes[index] << 1)
        finalbyte = int(self.ssid) << 1
        if self.reserved_bit_5:
            finalbyte = finalbyte | 32
        if self.reserved_bit_6:
            finalbyte = finalbyte | 64
        if self.command_repeat_bit:
            finalbyte = finalbyte | 128
        address_bytes.append(finalbyte)
        return bytes(address_bytes)

    def __str__(self) -> str:
        if self.ssid != '0':
            address = f'{self.callsign}-{self.ssid}'
        else:
            address = self.callsign
        if self.command_repeat_bit:
            address += "*"
        return address

    @property
    def call_with_ssid(self):
        return f'{self.callsign}-{self.ssid}'


class AX25AddressField(BaseModel):
    source: AX25Address
    destination: AX25Address
    path: List[AX25Address] = []
    length: int

    @classmethod
    def decode(cls, address_bytes: bytes) -> Self:
        destination = AX25Address.decode(address_bytes[0:7])
        # SOURCE
        source = AX25Address.decode(address_bytes[7:14])
        repeaters = []
        if len(address_bytes) > 14:
            for address in chunk(value_list=address_bytes[14:], chunk_size=7):
                repeaters.append(AX25Address.decode(bytes(address)))
        return cls(
            source=source,
            destination=destination,
            path=repeaters,
            length=len(address_bytes))

    def encode(self) -> bytes:
        field_bytes = bytearray()
        field_bytes += self.destination.encode()
        field_bytes += self.source.encode()
        for repeater in self.path:
            field_bytes += repeater.encode()
        field_bytes[-1] = field_bytes[-1] | 1
        return bytes(field_bytes)

    def __str__(self) -> str:
        if self.path:
            return f'{self.source.call_with_ssid}->{self.destination.call_with_ssid},{",".join([addr.call_with_ssid for addr in self.path])}'
        else:
            return f'{self.source.call_with_ssid}->{self.destination.call_with_ssid}'

    @property
    def unique_connection_id(self) -> str:
        return sha1(str(self).encode()).hexdigest()

    def get_response_field(self) -> Self:
        response_field = AX25AddressField(
            source=self.destination,
            destination=self.source,
            path=self.path[::-1],
            length=self.length
        )
        response_field.source.command_repeat_bit = True
        response_field.destination.command_repeat_bit = False
        for repeater in self.path:
            repeater.command_repeat_bit = False
        return response_field

class AX25FrameType(Flag):
    I_FRAME = 1
    S_FRAME = 2
    U_FRAME = 4
    SUP_RR = 8
    SUP_RNR = 16
    SUP_REJ = 32
    SUP_SREJ = 64
    UNN_SABME = 128
    UNN_SABM = 256
    UNN_DISC = 512
    UNN_DM = 1024
    UNN_UA = 2048
    UNN_FRMR = 4096
    UNN_UI = 8192
    UNN_XID = 16384
    UNN_TEST = 32768


class AX25Modulo(Enum):
    MOD_8 = 1
    MOD_128 = 2


class AX25ControlField(BaseModel):
    frame_type: AX25FrameType
    length: int
    poll_final: bool
    sequence: Optional[int]
    receive: Optional[int]

    @classmethod
    def decode(cls, field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> Self:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        match field_bytes[0] & 3:
            case 0 | 2:
                frame_type, sequence, receive = cls.decode_iframe_control(field_bytes, modulo)
                length = modulo.value
            case 1:
                frame_type, receive = cls.decode_sframe_control(field_bytes, modulo)
                sequence = None
                length = modulo.value
            case 3:
                frame_type = cls.decode_uframe_control(field_bytes, modulo)
                sequence, receive = None, None
                length = 1
        poll_final = bool(field_bytes[0] & 16)
        return cls(
            frame_type=frame_type,
            length=length,
            poll_final=poll_final,
            sequence=sequence,
            receive=receive
        )

    def encode(self, modulo: AX25Modulo = AX25Modulo.MOD_8):
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        else:
            match self.frame_type.value & 7:  # We only care at this point about I/U/S
                case AX25FrameType.I_FRAME.value:
                    return self.encode_iframe()
                case AX25FrameType.U_FRAME.value:
                    return self.encode_uframe()
                case AX25FrameType.S_FRAME.value:
                    return self.encode_sframe()

    def encode_iframe(self) -> bytes:
        frame_value = 0
        frame_value += self.sequence << 1
        frame_value += self.receive << 5
        frame_value += int(self.poll_final) << 4
        return frame_value.to_bytes()

    def encode_sframe(self) -> bytes:
        frame_value = 1
        match self.frame_type.value & 120:  # Only care about SUP flags
            case AX25FrameType.SUP_RR.value:
                pass
            case AX25FrameType.SUP_RNR.value:
                frame_value += 4
            case AX25FrameType.SUP_REJ.value:
                frame_value += 8
            case AX25FrameType.SUP_SREJ.value:
                frame_value += 12
        frame_value += int(self.poll_final) << 4
        frame_value += self.receive << 5
        return frame_value.to_bytes()

    def encode_uframe(self) -> bytes:
        frame_value = 3
        frame_value += int(self.poll_final) << 4
        match self.frame_type.value & 65408:  # Only care about UNN frame flags
            case AX25FrameType.UNN_SABME.value:
                frame_value += 108
            case AX25FrameType.UNN_SABM.value:
                frame_value += 44
            case AX25FrameType.UNN_DISC.value:
                frame_value += 64
            case AX25FrameType.UNN_DM.value:
                frame_value += 12
            case AX25FrameType.UNN_UA.value:
                frame_value += 96
            case AX25FrameType.UNN_FRMR.value:
                frame_value += 132
            case AX25FrameType.UNN_UI.value:
                pass
            case AX25FrameType.UNN_XID.value:
                frame_value += 172
            case AX25FrameType.UNN_TEST.value:
                frame_value += 224
        return frame_value.to_bytes()

    @staticmethod
    def decode_iframe_control(field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> Tuple[AX25FrameType, int, int]:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        frame_type = AX25FrameType.I_FRAME
        sequence = int((field_bytes[0] & 14) >> 1)
        response = int((field_bytes[0] & 224) >> 5)
        return (frame_type, sequence, response)

    @staticmethod
    def decode_sframe_control(field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> Tuple[AX25FrameType, int]:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        frame_type = AX25FrameType.S_FRAME
        match field_bytes[0] & 12:
            case 0:
                frame_type = frame_type | AX25FrameType.SUP_RR
            case 4:
                frame_type = frame_type | AX25FrameType.SUP_RNR
            case 8:
                frame_type = frame_type | AX25FrameType.SUP_REJ
            case 12:
                frame_type = frame_type | AX25FrameType.SUP_SREJ
        response = int((field_bytes[0] & 224) >> 5)
        return (frame_type, response)

    @staticmethod
    def decode_uframe_control(field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> AX25FrameType:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        frame_type = AX25FrameType.U_FRAME
        match field_bytes[0] & 236:
            case 108:
                frame_type = frame_type | AX25FrameType.UNN_SABME
            case 44:
                frame_type = frame_type | AX25FrameType.UNN_SABM
            case 64:
                frame_type = frame_type | AX25FrameType.UNN_DISC
            case 12:
                frame_type = frame_type | AX25FrameType.UNN_DM
            case 96:
                frame_type = frame_type | AX25FrameType.UNN_UA
            case 132:
                frame_type = frame_type | AX25FrameType.UNN_FRMR
            case 0:
                frame_type = frame_type | AX25FrameType.UNN_UI
            case 172:
                frame_type = frame_type | AX25FrameType.UNN_XID
            case 224:
                frame_type = frame_type | AX25FrameType.UNN_TEST
        return frame_type


class AX25Frame(BaseModel):
    modulo: AX25Modulo = AX25Modulo.MOD_8
    address_field: AX25AddressField
    control_field: AX25ControlField
    pid: Optional[AX25PID]
    information: Optional[bytes] = None

    @classmethod
    def decode(cls, frame: Union[bytes, KISSFrame], modulo: AX25Modulo = AX25Modulo.MOD_8):
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        if isinstance(frame, bytes):
            frame_data = frame
        elif isinstance(frame, KISSFrame):
            frame_data = frame.data
        else:
            raise RuntimeError('Invalid data type for frame. Expected bytes or KISSFrame')
        addr_field = cls.decode_address_field(frame_data)
        control_field = cls.decode_control_field(frame=frame_data, offset=addr_field.length, modulo=modulo)
        offset = addr_field.length + control_field.length
        pid = None
        if control_field.frame_type & (AX25FrameType.I_FRAME | AX25FrameType.UNN_UI):
            pid = AX25PID(frame_data[offset])
            offset += 1
        information = frame_data[offset:]
        return cls(
            modulo=modulo,
            address_field=addr_field,
            control_field=control_field,
            pid=pid,
            information=bytes(information)
        )

    def encode(self) -> bytes:
        frame_data = b''
        frame_data += self.address_field.encode()
        frame_data += self.control_field.encode(self.modulo)
        if self.pid:
            frame_data += self.pid.value.to_bytes()
        if self.information:
            frame_data += bytes(self.information)
        return frame_data

    @staticmethod
    def decode_control_field(frame: bytes, offset: int, modulo: AX25Modulo = AX25Modulo.MOD_8):
        return AX25ControlField.decode(frame[offset:(offset + modulo.value)])

    @staticmethod
    def decode_address_field(frame: bytes) -> AX25AddressField:
        address_field = []
        for byte in frame:
            address_field.append(byte)
            if byte & 1 == 1:
                break
        return AX25AddressField.decode(bytes(address_field))


class AX25ConnectionDirection(Enum):
    INCOMING = 1
    OUTGOING = 2


class AX25Connection():
    def __init__(self, local_callsign: str, remote_callsign: str, direction: AX25ConnectionDirection, logger = None) -> None:
        if not logger:
            logger = getLogger(f'AX25Connection[{local_callsign}<->{remote_callsign}]')
        self.logger = logger
        self._local = local_callsign
        self._remote = remote_callsign
        self._incoming = Queue()
        self._outgoing = Queue()
        self._direction = direction
        self.established = False

    def recieve(self, frame: AX25Frame):
        self._incoming.put_nowait(frame)

    def get_outgoing_frames(self) -> List[AX25Frame]:
        outgoing = []
        while not self._outgoing.empty():
            frame = self._outgoing.get_nowait()
            outgoing.append(frame)
        if outgoing:
            self.logger.debug(f'{len(outgoing)} outgoing frames')
        return outgoing

    @property
    def callsign(self) -> str:
        return self._local
    
    @property
    def direction(self) -> AX25ConnectionDirection:
        return self._direction

    def process(self) -> None:
        self._handle_incoming_frames()
        self._handle_timers()

    def _handle_sabme(self, frame: AX25Frame) -> None:
        self.logger.debug('Connection got SABME')
        # Currently no handling of Extended mode, always send DM
        response = AX25Frame(
            address_field=frame.address_field.get_response_field(),
            control_field=AX25ControlField(
                frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_DM,
                sequence=None,
                receive=None,
                length=frame.modulo.value,
                poll_final=frame.control_field.poll_final
            ),
            modulo=frame.modulo,
            pid=frame.pid,
            information=None
        )
        self._outgoing.put(response)

    def _handle_sabm(self, frame: AX25Frame) -> None:
        self.logger.debug('Connection got SABM')
        if self.established:
            response = AX25Frame(
                address_field=frame.address_field.get_response_field(),
                control_field=AX25ControlField(
                    frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_DM,
                    sequence=None,
                    receive=None,
                    length=frame.modulo.value,
                    poll_final=frame.control_field.poll_final
                ),
                modulo=frame.modulo,
                pid=frame.pid,
                information=None
            )
            self._outgoing.put(response)
        else:
            response = AX25Frame(
                address_field=frame.address_field.get_response_field(),
                control_field=AX25ControlField(
                    frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_UA,
                    sequence=None,
                    receive=None,
                    length=frame.modulo.value,
                    poll_final=frame.control_field.poll_final
                ),
                modulo=frame.modulo,
                pid=frame.pid,
                information=None
            )
            self._outgoing.put(response)
            self.established = True

    def _handle_incoming_frames(self) -> None:
        while not self._incoming.empty():
            frame = self._incoming.get_nowait()
            if frame.control_field.frame_type == (AX25FrameType.U_FRAME | AX25FrameType.UNN_SABM):
                self._handle_sabm(frame)
            elif frame.control_field.frame_type == (AX25FrameType.U_FRAME | AX25FrameType.UNN_SABME):
                self._handle_sabme(frame)

    def _handle_timers(self) -> None:
        pass


class AX25Client():
    def __init__(self, tnc: KISSClient, retry_count: int = 5, promiscuous: bool = False, logger = None) -> None:
        if not logger:
            logger = getLogger('AX25Client')
        self.logger = logger
        self._tnc = tnc
        self._retry_count = retry_count
        self._tnc.decode_callback = self.recieve_frame
        self._stop_requested = False
        self._running = False
        self._promiscuous = promiscuous
        self._connections = {}
        self._listeners = []

    async def recieve_frame(self, frame: KISSFrame):
        axframe = AX25Frame.decode(frame)
        self.logger.debug(f'Got frame {str(axframe.address_field.source)}->{str(axframe.address_field.destination)}')
        if axframe.address_field.unique_connection_id in self._connections.keys():
            self.logger.debug(f'Accepted frame {str(axframe.address_field)} for existing connection')
            self._connections[axframe.address_field.unique_connection_id].recieve(axframe)
        elif axframe.address_field.destination.call_with_ssid in self._listeners:
            self.logger.debug(f'Accepted frame {str(axframe.address_field)} for listener')
            self._loop.create_task(self.listener_accept_connection(axframe))

    async def listener_accept_connection(self, frame: AX25Frame):
        new_connection = AX25Connection(
            local_callsign=frame.address_field.destination.call_with_ssid,
            remote_callsign=frame.address_field.source.call_with_ssid,
            direction=AX25ConnectionDirection.INCOMING
        )
        new_connection.recieve(frame)
        self._connections[frame.address_field.unique_connection_id] = new_connection

    async def main_loop(self):
        while True:
            outgoing_frames = []
            for connection in self._connections:
                self._connections[connection].process()
                outgoing_frames += self._connections[connection].get_outgoing_frames()
            for frame in outgoing_frames:
                await self._tnc.send(KISSFrame(data=frame.encode(), command=KISSCommand.DATA_FRAME, port=0))  #TODO: Handle more than 1 KISS port
            if self._stop_requested:
                self._running = False
                return
            await asyncio.sleep(0.1)

    async def start(self):
        self._loop = asyncio.get_running_loop()
        self._loop.create_task(self._tnc.start_listen())
        self._loop.create_task(self.main_loop())
        self._running = True

    async def stop(self, close=True):
        self._stop_requested = True
        self._tnc.stop_listen(close)

    def add_listener(self, callsign: str) -> None:
        if callsign not in self._listeners:
            self._listeners.append(callsign)