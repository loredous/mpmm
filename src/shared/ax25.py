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
import gc
from hashlib import sha1
import inspect
from typing import Callable, List, Optional, Self, Tuple, Union, Dict
from queue import PriorityQueue, Queue, Empty
from logging import Logger, getLogger
import asyncio
from uuid import UUID, uuid4
from time import monotonic_ns

from pydantic import BaseModel, conint
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
    command_repeat_bit: bool = False

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
    
    @classmethod
    def from_callsign(cls, callsign: str) -> Self:
        if "-" in callsign:
            components = callsign.split('-')
            call = components[0]
            ssid = components[1]
        else:
            call = callsign
            ssid = 0
        return cls(
            callsign=call,
            ssid=ssid
        )


class AX25AddressField(BaseModel):
    source: AX25Address
    destination: AX25Address
    path: List[AX25Address] = []
    length: Optional[int]

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
    length: Optional[int]
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


class AX25FrameFactory():
    @staticmethod
    def dm_response(axframe: AX25Frame, poll_final: bool = False):
        addr = axframe.address_field.get_response_field()
        control = AX25ControlField(
            frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_DM,
            poll_final=poll_final
        )
        frame = AX25Frame(
            address_field=addr,
            control_field=control,
            pid=AX25PID.NONE
        )
        return frame
    
    @staticmethod
    def ua_response(axframe: AX25Frame, poll_final: bool = False):
        addr = axframe.address_field.get_response_field()
        control = AX25ControlField(
            frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_UA,
            poll_final=poll_final
        )
        frame = AX25Frame(
            address_field=addr,
            control_field=control,
            pid=AX25PID.NONE
        )
        return frame

##### AX.25 STATE MACHINES #####


class AX25ClientFrame(BaseModel):
    axframe: AX25Frame
    port: conint(ge=0,le=15) = 0
    priority: conint(ge=0,le=10) = 5

    def __lt__(self, other: Self):
        if isinstance(other, AX25ClientFrame):
            return self.priority < other.priority


class AX25Client():

    def __init__(self, tnc: KISSClient, logger: Logger = None, client_id: UUID = uuid4()) -> None:
        if not logger:
            logger = getLogger(f'AX25Client[{client_id}]')
        self.logger = logger
        self._id = client_id
        self._tnc = tnc
        self._tnc.decode_callback = self.recieve_frame
        self._data_callbacks: "List[Callable[[AX25Frame, Self, int],None]]" = [] 
        self._stop_requested = False
        self._running = False
        self._outgoing: "Queue[AX25ClientFrame]" = PriorityQueue()

    @property
    def id(self):
        return self._id

    async def recieve_frame(self, frame: KISSFrame):
        self.logger.debug('Got KISS frame, attempting to decode as AX25')
        try:
            axframe = AX25Frame.decode(frame)
            self.logger.debug(f'Got frame {str(axframe.address_field.source)}->{str(axframe.address_field.destination)}')
            for callback in self._data_callbacks:
                callback(axframe, self, frame.port)
        except Exception:
            self.logger.exception('Exception when attempting to decode KISS frame!')

    async def main_loop(self):
        while True:
            while not self._outgoing.empty():
                frame = self._outgoing.get_nowait()
                await self._tnc.send(KISSFrame(data=frame.axframe.encode(), command=KISSCommand.DATA_FRAME, port=frame.port))  #TODO: Handle more than 1 KISS port
            if self._stop_requested:
                self.logger.info('Answering stop')
                self._running = False
                return
            await asyncio.sleep(0.1)

    def queue_for_sending(self, client_frame: AX25ClientFrame) -> None:
        if isinstance(client_frame, AX25ClientFrame):
            self._outgoing.put_nowait(client_frame)
        else:
            raise TypeError('client_frame must be of type AX25ClientFrame')

    def add_data_callback(self, data_callback: Callable[[AX25Frame, Self, int],None]) -> None:
        if callable(data_callback):
            self._data_callbacks.append(data_callback)
    
    def remove_data_callback(self, data_callback: Callable[[AX25Frame, Self, int],None]) -> None:
        if callable(data_callback):
            self._data_callbacks.remove(data_callback)

    async def start(self):
        self.logger.info('Start requested')
        self._loop = asyncio.get_running_loop()
        self._loop.create_task(self._tnc.start_listen())
        self._loop.create_task(self.main_loop())
        self._running = True

    async def stop(self, close=True):
        self.logger.info('Stop requested')
        self._stop_requested = True
        self._tnc.stop_listen(close)


class AX25ConnectionState(Enum):
    DISCONNECTED = 0
    AWAITING_CONNECTION = 1
    AWAITING_RELEASE = 2
    CONNECTED = 3
    TIMER_RECOVERY = 4


class AX25Data(BaseModel):
    data: str
    source_call: str
    dest_call: str

    @classmethod
    def from_frame(cls, axframe: AX25Frame):
        return cls(
            data=axframe.information.decode(),
            source_call=axframe.address_field.source.call_with_ssid,
            dest_call=axframe.address_field.source.call_with_ssid,
        )


class AX25Connection():

    def __init__(self, local_callsign: str, remote_callsign: str, client: AX25Client, port: int, logger=None) -> None:
        self._local = local_callsign
        self._remote = remote_callsign
        self._client = client
        self._port = port
        if not logger:
            logger = getLogger(f'AX25Connection[{str(self)}]')
        self._logger = logger
        self._incoming = Queue()
        self._state = AX25ConnectionState.DISCONNECTED
        self._active = False
        self._data_available_callbacks: "List[Callable[[AX25Data],None]]" = []
        self._ui_callbacks: "List[Callable[[AX25Data],None]]" = []
        self._next_sequence = 0
        self._last_ack = 0
        self._last_recieved = 0
        self._retry_count = 10
        self._srej = True
        self._ifield_len = 2048
        self._window_size = 7
        self._ack_timer = 3000
        self._extended = True
        self._round_trip_timer = 15000
        self._outstanding_frame_time = 2000  # T1
        self._idle_time = 60000  # T2
        self._idle_timer_expires = 0
        self._outstanding_frame_expires = 0

    def __str__(self) -> str:
        return f'{self._local}<->{self._remote}@{str(self._client.id)}:{self._port}'

    @staticmethod
    def get_connection_id(local_callsign: str, remote_callsign: str, client_id: UUID, port: int) -> str:
        return sha1(f'{local_callsign}<->{remote_callsign}@{str(client_id)}:{port}'.encode()).hexdigest()
    
    @property
    def connection_id(self):
        return sha1(str(self).encode()).hexdigest()

    @property
    def active(self) -> bool:
        return self._active

    def recieve(self, frame: AX25Frame):
        self._incoming.put_nowait(frame)

    def send(self, frame: AX25Frame, priority: int = 5):
        client_frame = AX25ClientFrame(
            axframe=frame,
            port=self._port,
            priority=priority
        )
        self._client.queue_for_sending(client_frame=client_frame)

    @property
    def connection_state(self) -> AX25ConnectionState:
        return self._state

    async def start(self):
        self._logger.debug(f'Starting handling loop')
        loop = asyncio.get_running_loop()
        self._active = True
        loop.create_task(self.handling_loop())

    def stop(self, abort: bool = False):
        if abort:
            self._logger.warn('Abort requested for connection')
            self._active = False
        else:
            self._logger.debug('Stop requested for connection')
            #DO MORE HERE
            self._state = AX25ConnectionState.AWAITING_RELEASE

    async def handling_loop(self):
        while self._active:
            self._handle_incoming_frames()
            self._handle_timers()
            await asyncio.sleep(0.1)

    def _handle_incoming_frames(self):
        while not self._incoming.empty():
            frame = self._incoming.get_nowait()
            self._logger.debug(f'Got frame {frame}')
            match self._state:
                case AX25ConnectionState.DISCONNECTED:
                    self._disconnected_state_frame_handler(frame)
                case AX25ConnectionState.CONNECTED:
                    self._connected_state_frame_handler(frame)
                case AX25ConnectionState.AWAITING_CONNECTION:
                    pass
                case AX25ConnectionState.AWAITING_RELEASE:
                    pass
                case AX25ConnectionState.TIMER_RECOVERY:
                    pass

    def _handle_timers(self):
        pass

    def _reset_idle_timer(self):
        self._idle_timer_expires = monotonic_ns() + (self._idle_time * 1000000)

    def _reset_outstanding_frame_timer(self):
        self._outstanding_frame_expires = monotonic_ns() + (self._outstanding_frame_time * 1000000)

    def _disconnected_state_frame_handler(self, frame: AX25Frame):
        if AX25FrameType.UNN_DM in frame.control_field.frame_type:
            self._logger.debug(f'Ignoring DM frame {str(frame.address_field)}')
        elif AX25FrameType.UNN_UI in frame.control_field.frame_type:
            if frame.control_field.poll_final:
                self._logger.debug(f'Sending DM response to UI frame {str(frame.address_field)} with Poll/Final set')
                frame = AX25FrameFactory.dm_response(axframe=frame, poll_final=True)
                self._client.queue_for_sending(AX25ClientFrame(axframe=frame, port=self._port, priority=1))
            self._logger.debug(f'Sending frame {str(frame.address_field)} to UI callbacks')
            for callback in self._ui_callbacks:
                callback(AX25Data.from_frame(frame))
        elif AX25FrameType.UNN_DISC in frame.control_field.frame_type:
            self._logger.debug(f'Sending DM response to DISC frame {str(frame.address_field)}')
            frame = AX25FrameFactory.dm_response(axframe=frame, poll_final=frame.control_field.poll_final)
            self._client.queue_for_sending(AX25ClientFrame(axframe=frame, port=self._port, priority=1))
        elif AX25FrameType.UNN_SABME in frame.control_field.frame_type:
            self._logger.debug(f'Acknowledging SABME request {str(frame.address_field)}')
            frame = AX25FrameFactory.ua_response(axframe=frame, poll_final=frame.control_field.poll_final)
            self._client.queue_for_sending(AX25ClientFrame(axframe=frame, port=self._port, priority=1))
            self._next_sequence = 0
            self._last_ack = 0
            self._last_recieved = 0
            self._reset_idle_timer()
            self._state = AX25ConnectionState.CONNECTED
        elif AX25FrameType.UNN_SABM in frame.control_field.frame_type:
            self._logger.debug(f'Acknowledging SABM request {str(frame.address_field)}')
            frame = AX25FrameFactory.ua_response(axframe=frame, poll_final=frame.control_field.poll_final)
            self._client.queue_for_sending(AX25ClientFrame(axframe=frame, port=self._port, priority=1))
            self._next_sequence = 0
            self._last_ack = 0
            self._last_recieved = 0
            self._extended = False
            self._srej = False
            self._window_size = 4
            self._reset_idle_timer()
            self._state = AX25ConnectionState.CONNECTED
        elif frame.address_field.source.command_repeat_bit == True:
            self._logger.debug(f'Sending DM response to command frame {str(frame.address_field)}')
            frame = AX25FrameFactory.dm_response(axframe=frame, poll_final=frame.control_field.poll_final)
            self._client.queue_for_sending(AX25ClientFrame(axframe=frame, port=self._port, priority=1))

    def _connected_state_frame_handler(self, frame: AX25Frame):
        if AX25FrameType.I_FRAME in frame.control_field.frame_type:
            if self._next_sequence >= self._last_ack + self._window_size:
                self._logger.debug('Too many oustanding frames')


class AX25Listener(BaseModel):
    callsign: str
    incoming_callback: Callable[[AX25Connection], None]


class AX25Controller():
    def __init__(self, logger: Logger = None, controller_id: UUID = uuid4()) -> None:
        if not logger:
            logger = getLogger(f'AX25Controller[{controller_id}]')
        self._logger = logger
        self._id = controller_id
        self._connections: "Dict[str,AX25Connection]" = {}
        self._clients: "List[AX25Client]" = []
        self._listeners: "List[AX25Listener]" = []
        self._ui_callbacks: "List[Callable[[AX25Frame, AX25Client, int], None]]" = []
        self._shutdown_requested = False
        self._active = True

    @property
    def id(self):
        return self._id

    @property
    def clients(self):
        return self._clients

    def add_listener(self, listener: AX25Listener) -> None:
        if listener.callsign in [listen.callsign for listen in self._listeners]:
            raise NameError(f'Listener with identity {listener.callsign} already exists.')
        self._logger.info(f'Adding listener for callsign {listener.callsign}')
        self._listeners.append(listener)

    def remove_listener(self, callsign: str) -> None:
        if callsign in [listen.callsign for listen in self._listeners]:
            self.logger.info(f'Removing listener for {callsign}')
            [listen.callsign for listen in self._listeners]
            self._listeners

    def add_client(self, client: AX25Client) -> None:
        if issubclass(type(client), AX25Client):
            self._clients.append(client)
            client.add_data_callback(self.data_recieved)
            loop = asyncio.get_event_loop()
            loop.create_task(client.start())

    def remove_client(self, client: AX25Client) -> None:
        if issubclass(client, AX25Client):
            self._clients.remove(client)
            client.remove_data_callback(self.data_recieved)
            loop = asyncio.get_running_loop()
            loop.create_task(client.stop())

    def add_ui_callback(self, callback: Callable[[AX25Frame, AX25Client, int], None]):
        if callable(callback):
            self._ui_callbacks.append(callback)

    def remove_ui_callback(self, callback: Callable[[AX25Frame, AX25Client, int], None]):
        if callable(callback):
            self._ui_callbacks.remove(callback)

    def send_ui_frame(self, local_callsign: str, remote_callsign: str, data: str, client: AX25Client, port: int = 0, priority: int = 5, path: List[str] = [], poll: bool = False):
        source = AX25Address.from_callsign(local_callsign)
        dest = AX25Address.from_callsign(remote_callsign)
        send_path = []
        for call in path:
            send_path.append(AX25Address.from_callsign(call))
        addr_field = AX25AddressField(source=source, destination=dest, path=send_path)
        control = AX25ControlField(
            frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_UI,
            poll_final=poll
        )
        frame = AX25Frame(
            address_field=addr_field,
            control_field=control,
            pid=AX25PID.NONE,
            information=data.encode()
        )
        client_frame = AX25ClientFrame(axframe=frame, port=port, priority=priority)
        self._logger.debug(f'Sending UI frame {frame} from client {client}:{port}')
        client.queue_for_sending(client_frame=client_frame)

    def data_recieved(self, axframe: AX25Frame, source: AX25Client, kiss_port: int):
        connection_id = AX25Connection.get_connection_id(local_callsign=axframe.address_field.destination.call_with_ssid, remote_callsign=axframe.address_field.source.call_with_ssid, client_id=source.id, port=kiss_port)
        self._logger.debug(f'Got frame {str(axframe.address_field)}')
        if connection_id in self._connections.keys():
            connection = self._connections[connection_id]
            self._logger.debug(f'Sending frame {str(axframe.address_field)} to existing connection {str(connection)}')
            connection.recieve(axframe)
        elif axframe.control_field.frame_type & AX25FrameType.UNN_UI:
            if axframe.control_field.poll_final:
                self._logger.debug(f'Sending DM response to UI frame {str(axframe.address_field)} with Poll/Final set')
                frame = AX25FrameFactory.dm_response(axframe=axframe, poll_final=True)
                source.queue_for_sending(AX25ClientFrame(axframe=frame, port=kiss_port, priority=1))
            self._logger.debug(f'Sending frame {str(axframe.address_field)} to UI callbacks')
            for callback in self._ui_callbacks:
                callback(axframe, source, kiss_port)
        elif axframe.address_field.destination.call_with_ssid in [listener.callsign for listener in self._listeners]:
            listener = [listener for listener in self._listeners][0]
            connection = AX25Connection(
                local_callsign=axframe.address_field.destination.call_with_ssid,
                remote_callsign=axframe.address_field.source.call_with_ssid,
                client=source,
                port=kiss_port
            )
            self._logger.debug(f'Sending frame {str(axframe.address_field)} to new connection {str(connection)}')
            connection.recieve(axframe)
            self._connections[connection.connection_id] = connection
            listener.incoming_callback(connection)
            loop = asyncio.get_running_loop()
            loop.create_task(connection.start())
        else:
            self._logger.debug(f'Ignoring frame {str(axframe.address_field)}')

    def start(self) -> None:
        self._logger.info('Start requested. Starting handling loop')
        loop = asyncio.get_event_loop()
        loop.create_task(self.handling_loop())

    def stop(self, abort=False):
        if abort:
            self._logger.warn('Abort requested. Aborting all connections.')
            for connection in self._connections.values():
                connection.stop(abort=True)
            self._active = False
        else:
            self._logger.info('Stop requested')
            self._shutdown_requested = True

    async def handling_loop(self):
        while self._active:
            for connection in self._connections.values():
                if not connection.active:
                    self._logger.debug(f'Destroying inactive connection {str(connection)}')
                    self._connections.pop(connection.connection_id)
                    del connection
            gc.collect()
            if self._shutdown_requested:
                for connection in self._connections.values():
                    if connection.connection_state != AX25ConnectionState.AWAITING_RELEASE:
                        self._logger.debug(f'Requesting graceful shutdown of connection {str(connection)}')
                        connection.stop()
                if len(self._connections.items()) == 0:
                    self._logger.info('Graceful shutdown complete.')
                    return
            await asyncio.sleep(5)
