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
import time
from typing import Callable, List, Optional, Self, Tuple, Union, Dict
from queue import PriorityQueue, Queue
from logging import Logger, getLogger
import asyncio
from uuid import UUID, uuid4
from time import monotonic_ns

from pydantic import BaseModel, ConfigDict, conint, Field
from shared.utils import chunk, get_time_ms
from shared.kiss import KISSCommand, KISSFrame, KISSClient

##### AX.25 STATE MACHINES ##### noqa: E266


class AX25ClientFrame(BaseModel):
    axframe: AX25Frame
    port: conint(ge=0, le=15) = 0
    priority: conint(ge=0, le=10) = 5

    def __lt__(self, other: Self):
        if isinstance(other, AX25ClientFrame):
            return self.priority < other.priority


class AX25Client():
    def __init__(
        self, tnc: KISSClient, logger: Logger = None, client_id: UUID = uuid4()
    ) -> None:
        if not logger:
            logger = getLogger(f"AX25Client[{client_id}]")
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
        self.logger.debug("Got KISS frame, attempting to decode as AX25")
        try:
            axframe = AX25Frame.decode(frame)
            self.logger.debug(
                f"Got frame {str(axframe.address_field.source)}->{str(axframe.address_field.destination)}"
            )
            for callback in self._data_callbacks:
                callback(axframe, self, frame.port)
        except Exception:
            self.logger.exception("Exception when attempting to decode KISS frame!")

    async def main_loop(self):
        while True:
            while not self._outgoing.empty():
                frame = self._outgoing.get_nowait()
                await self._tnc.send(
                    KISSFrame(
                        data=frame.axframe.encode(),
                        command=KISSCommand.DATA_FRAME,
                        port=frame.port,
                    )
                )
            if self._stop_requested:
                self.logger.info("Answering stop")
                self._running = False
                return
            await asyncio.sleep(0.1)

    def queue_for_sending(self, client_frame: AX25ClientFrame) -> None:
        if isinstance(client_frame, AX25ClientFrame):
            self._outgoing.put_nowait(client_frame)
        else:
            raise TypeError("client_frame must be of type AX25ClientFrame")

    def add_data_callback(
        self, data_callback: Callable[[AX25Frame, Self, int], None]
    ) -> None:
        if callable(data_callback):
            self._data_callbacks.append(data_callback)

    def remove_data_callback(
        self, data_callback: Callable[[AX25Frame, Self, int], None]
    ) -> None:
        if callable(data_callback):
            self._data_callbacks.remove(data_callback)

    async def start(self):
        self.logger.info("Start requested")
        self._loop = asyncio.get_running_loop()
        self._loop.create_task(self._tnc.start_listen())
        self._loop.create_task(self.main_loop())
        self._running = True

    async def stop(self, close=True):
        self.logger.info("Stop requested")
        self._stop_requested = True
        self._tnc.stop_listen(close)





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


class FrameAwaitingAck(BaseModel):
    frame: AX25ClientFrame
    timeout: int = 15000
    timer_expiry: int = None

    def model_post_init(self, __context) -> None:
        self.reset_timer()

    def reset_timer(self, timeout:int = None):
        self.timer_expiry =  get_time_ms() + timeout



class AX25Connection(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    local_callsign: str = Field(frozen=True) # Local end callsign for this connection
    remote_callsign: str = Field(frozen=True) # Remote end callsign for this connection
    client: AX25Client  # Client handling the physical communication for this connection
    port: int   # Port on the client for this connection
    retry_count: int = 10 # Maximum number of retries for sending a frame
    ifield_length: int = 2048 # Maximum number of bytes in an I frame data field
    keepalive: int = 60000 # How often to send a keepalive packet (in ms)

    _logger: Logger = None  # Python logger
    _incoming: Queue = Queue()  # Queue for holding incoming frames awaiting handling
    _awaiting_ack: List[FrameAwaitingAck] = [] # List of frames awaiting acknowledgement (T1 Analogue)
    _state: AX25ConnectionState = AX25ConnectionState.DISCONNECTED  # Current State of the connection
    _active: bool = False   # Control flag for the internal handling loop
    _data_callbacks: List[Callable[[AX25Data],None]] = []   # List of callbacks requesting data frames from this connection
    _ui_callbacks: List[Callable[[AX25Data],None]] = [] # List of callbacks requesting UI frames from this connection

    _reject_exception: bool = False # Has a REJ frame been sent to the remote station
    _selective_reject_exception: bool = False # Has a SREJ frame been sent to the remote station
    _smoothed_round_trip_time: int = 15000 # Average RTT for frames in this connection in ms

    _keepalive_timer_trigger: int = 0 # (T3) Timestamp (Epoch ms) for keepalive

#     def __init__(
#         self,
#         local_callsign: str,
#         remote_callsign: str,
#         client: AX25Client,
#         port: int,
#         logger=None,
#     ) -> None:
#         self._local = local_callsign
#         self._remote = remote_callsign
#         self._client = client
#         self._port = port
#         
#         self._logger = logger
#         self._incoming = Queue()
#         self._state = AX25ConnectionState.DISCONNECTED
#         self._active = False
#         self._data_available_callbacks: "List[Callable[[AX25Data],None]]" = []
#         self._ui_callbacks: "List[Callable[[AX25Data],None]]" = []
#         self._next_sequence = 0
#         self._last_ack = 0
#         self._last_recieved = 0
#         self._retry_count = 10
#         self._srej = True
#         self._ifield_len = 2048
#         self._window_size = 7
#         self._ack_timer = 3000
#         self._extended = True
#         self._round_trip_timer = 15000
#         self._outstanding_frame_time = 2000  # T1
#         self._idle_time = 60000  # T2
#         self._idle_timer_expires = 0
#         self._outstanding_frame_expires = 0

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self._logger:
            self._logger = getLogger(f"AX25Connection[{str(self)}]")

    def __str__(self) -> str:
        return f"{self.local_callsign}<->{self.remote_callsign}@{str(self.client.id)}:{self._port}"

    def _reset_keepalive_timer(self, stop=False):
        if stop:
            self._keepalive_timer_trigger = -1
        else:
            self._keepalive_timer_trigger = get_time_ms() + self.keepalive

    def _ack_pending(self) -> bool:
        return bool(self._awaiting_ack)

    @staticmethod
    def get_connection_id(
        local_callsign: str, remote_callsign: str, client_id: UUID, port: int
    ) -> str:
        return sha1(
            f"{local_callsign}<->{remote_callsign}@{str(client_id)}:{port}".encode()
        ).hexdigest()

    @property
    def connection_id(self):
        return AX25Connection.get_connection_id(self.local_callsign, self.remote_callsign, self.client.id, self.port)
    
    @property
    def connection_state(self) -> AX25ConnectionState:
        return self._state

    @property
    def active(self) -> bool:
        return self._active

    def recieve(self, frame: AX25Frame):
        self._incoming.put_nowait(frame)

    def send(self, frame: AX25Frame, priority: int = 5, expect_ack: bool=False):
        client_frame = AX25ClientFrame(
            axframe=frame, port=self._port, priority=priority
        )
        self.client.queue_for_sending(client_frame=client_frame)
        if expect_ack:
            self._awaiting_ack.append(client_frame)

    async def start(self):
        self._logger.debug("Starting handling loop")
        loop = asyncio.get_running_loop()
        self._active = True
        loop.create_task(self.handling_loop())

    def stop(self, abort: bool = False):
        if abort:
            self._logger.warn("Abort requested for connection")
            self._reset_keepalive_timer(stop=True)
            self._reset_outstanding_frame_timeout(stop=True)
            self.send(AX25FrameFactory.disc(),1)
            self._awaiting_ack = []
            self._active = False
            self._state = AX25ConnectionState.DISCONNECTED
        else:
            self._logger.debug("Stop requested for connection")
            self._reset_keepalive_timer(stop=True)
            self._reset_outstanding_frame_timeout()

            self.send(AX25FrameFactory.disc(),1)
            # DO MORE HERE
            self._state = AX25ConnectionState.AWAITING_RELEASE

    async def handling_loop(self):
        while self._active:
            self._handle_incoming_frames()
            self._handle_timers()
            await asyncio.sleep(0.1)

    def _handle_incoming_frames(self):
        while not self._incoming.empty():
            frame = self._incoming.get_nowait()
            self._logger.debug(f"Got frame {frame}")
            match self._state:
                case AX25ConnectionState.DISCONNECTED:
                    self._disconnected_state_frame_handler(frame)
                case AX25ConnectionState.CONNECTED:
                    self._connected_state_frame_handler(frame)
                case AX25ConnectionState.AWAITING_CONNECTION:
                    self._logger.debug("Got frame in awaiting connection state... This should never happen")
                case AX25ConnectionState.AWAITING_RELEASE:
                    self._awaiting_release_frame_handler(frame)
                case AX25ConnectionState.TIMER_RECOVERY:
                    pass

    def _handle_timers(self): # TODO: Handle timers!
        pass

    def _disconnected_state_frame_handler(self, frame: AX25Frame):
        if AX25FrameType.UNN_DM in frame.control_field.frame_type:
            self._logger.debug(f"Ignoring DM frame {str(frame.address_field)}")
        elif AX25FrameType.UNN_UI in frame.control_field.frame_type:
            if frame.control_field.poll_final:
                self._logger.debug(
                    f"Sending DM response to UI frame {str(frame.address_field)} with Poll/Final set"
                )
                resp_frame = AX25FrameFactory.dm_response(axframe=frame, poll_final=True)
                self.client.queue_for_sending(
                    AX25ClientFrame(axframe=resp_frame, port=self._port, priority=1)
                )
            self._logger.debug(
                f"Sending frame {str(frame.address_field)} to UI callbacks"
            )
            for callback in self._ui_callbacks:
                callback(AX25Data.from_frame(frame))
        elif AX25FrameType.UNN_DISC in frame.control_field.frame_type:
            self._logger.debug(
                f"Sending DM response to DISC frame {str(frame.address_field)}"
            )
            resp_frame = AX25FrameFactory.dm_response(
                axframe=frame, poll_final=frame.control_field.poll_final
            )
            self.client.queue_for_sending(
                AX25ClientFrame(axframe=resp_frame, port=self._port, priority=1)
            )
        elif AX25FrameType.UNN_SABME in frame.control_field.frame_type:
            self._logger.debug(
                f"Cannot Establish V2.2 connection. Rejecting SABME {str(frame.address_field)}"
            )
            resp_frame = AX25FrameFactory.dm_response(frame)
            self.client.queue_for_sending(
                AX25ClientFrame(axframe=resp_frame, port=self._port, priority=1)
            )
        elif AX25FrameType.UNN_SABM in frame.control_field.frame_type:
            self._logger.debug(f"Acknowledging SABM request {str(frame.address_field)}")
            resp_frame = AX25FrameFactory.ua_response(
                axframe=frame, poll_final=frame.control_field.poll_final
            )
            self.client.queue_for_sending(
                AX25ClientFrame(axframe=resp_frame, port=self._port, priority=1)
            )
            self._next_sequence = 0 # TODO: FIX THIS SHIT
            self._last_ack = 0
            self._last_recieved = 0
            self._extended = False
            self._srej = False
            self._window_size = 4
            self._reset_idle_timer()
            self._state = AX25ConnectionState.CONNECTED
        elif frame.address_field.source.command_repeat_bit:
            self._logger.debug(
                f"Sending DM response to command frame {str(frame.address_field)}"
            )
            frame = AX25FrameFactory.dm_response(
                axframe=frame, poll_final=frame.control_field.poll_final
            )
            self.client.queue_for_sending(
                AX25ClientFrame(axframe=frame, port=self._port, priority=1)
            )

    def _awaiting_release_frame_handler(self, frame: AX25Frame):
        if AX25FrameType.UNN_SABM in frame.control_field.frame_type or AX25FrameType.UNN_SABME in frame.control_field.frame_type:
            resp_frame = AX25FrameFactory.dm_response(axframe=frame, poll_final=True)
            self._logger.debug(
                    f"Sending DM response to SABM(E) frame {str(frame.address_field)} with Poll/Final set"
                )
            self.client.queue_for_sending(
                    AX25ClientFrame(axframe=resp_frame, port=self._port, priority=1)
                    )
        elif AX25FrameType.UNN_DISC in frame.control_field.frame_type:
            self._logger.debug(
                    f"Sending UA response to DISC frame {str(frame.address_field)} with Poll/Final set"
                )
            resp_frame = AX25FrameFactory.ua_response(axframe=frame)
            self.client.queue_for_sending(
                    AX25ClientFrame(axframe=resp_frame, port=self._port)
            )
        elif (
              AX25FrameType.I_FRAME in frame.control_field.frame_type or
              AX25FrameType.SUP_RR in frame.control_field.frame_type or
              AX25FrameType.SUP_RNR in frame.control_field.frame_type or
              AX25FrameType.SUP_REJ in frame.control_field.frame_type or
              AX25FrameType.SUP_SREJ in frame.control_field.frame_type
             ):
            self._logger.debug(
                    f"Sending DM response to frame {str(frame.address_field)} with matching Poll/Final set"
                )
            resp_frame = AX25FrameFactory.dm_response(axframe=frame, poll_final=frame.control_field.poll_final)
            self.client.queue_for_sending(
                    AX25ClientFrame(axframe=resp_frame, port=self._port)
            )

    def _connected_state_frame_handler(self, frame: AX25Frame):
        if AX25FrameType.I_FRAME in frame.control_field.frame_type:
            if self._next_sequence >= self._last_ack + self._window_size:
                self._logger.debug("Too many oustanding frames")


class AX25Listener(BaseModel):
    callsign: str
    incoming_callback: Callable[[AX25Connection], None]


class AX25Controller:
    def __init__(self, logger: Logger = None, controller_id: UUID = uuid4()) -> None:
        if not logger:
            logger = getLogger(f"AX25Controller[{controller_id}]")
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
            raise NameError(
                f"Listener with identity {listener.callsign} already exists."
            )
        self._logger.info(f"Adding listener for callsign {listener.callsign}")
        self._listeners.append(listener)

    def remove_listener(self, callsign: str) -> None:
        if callsign in [listen.callsign for listen in self._listeners]:
            self.logger.info(f"Removing listener for {callsign}")
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

    def remove_ui_callback(
        self, callback: Callable[[AX25Frame, AX25Client, int], None]
    ):
        if callable(callback):
            self._ui_callbacks.remove(callback)

    def send_ui_frame(
        self,
        local_callsign: str,
        remote_callsign: str,
        data: str,
        client: AX25Client,
        port: int = 0,
        priority: int = 5,
        path: List[str] = [],
        poll: bool = False,
    ):
        source = AX25Address.from_callsign(local_callsign)
        dest = AX25Address.from_callsign(remote_callsign)
        send_path = []
        for call in path:
            send_path.append(AX25Address.from_callsign(call))
        addr_field = AX25AddressField(source=source, destination=dest, path=send_path)
        control = AX25ControlField(
            frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_UI, poll_final=poll
        )
        frame = AX25Frame(
            address_field=addr_field,
            control_field=control,
            pid=AX25PID.NONE,
            information=data.encode(),
        )
        client_frame = AX25ClientFrame(axframe=frame, port=port, priority=priority)
        self._logger.debug(f"Sending UI frame {frame} from client {client}:{port}")
        client.queue_for_sending(client_frame=client_frame)

    def data_recieved(self, axframe: AX25Frame, source: AX25Client, kiss_port: int):
        connection_id = AX25Connection.get_connection_id(
            local_callsign=axframe.address_field.destination.call_with_ssid,
            remote_callsign=axframe.address_field.source.call_with_ssid,
            client_id=source.id,
            port=kiss_port,
        )
        self._logger.debug(f"Got frame {str(axframe.address_field)}")
        if connection_id in self._connections.keys():
            connection = self._connections[connection_id]
            self._logger.debug(
                f"Sending frame {str(axframe.address_field)} to existing connection {str(connection)}"
            )
            connection.recieve(axframe)
        elif axframe.control_field.frame_type & AX25FrameType.UNN_UI:
            if axframe.control_field.poll_final:
                self._logger.debug(
                    f"Sending DM response to UI frame {str(axframe.address_field)} with Poll/Final set"
                )
                frame = AX25FrameFactory.dm_response(axframe=axframe, poll_final=True)
                source.queue_for_sending(
                    AX25ClientFrame(axframe=frame, port=kiss_port, priority=1)
                )
            self._logger.debug(
                f"Sending frame {str(axframe.address_field)} to UI callbacks"
            )
            for callback in self._ui_callbacks:
                callback(axframe, source, kiss_port)
        elif axframe.address_field.destination.call_with_ssid in [
            listener.callsign for listener in self._listeners
        ]:
            listener = [listener for listener in self._listeners][0]
            connection = AX25Connection(
                local_callsign=axframe.address_field.destination.call_with_ssid,
                remote_callsign=axframe.address_field.source.call_with_ssid,
                client=source,
                port=kiss_port,
            )
            self._logger.debug(
                f"Sending frame {str(axframe.address_field)} to new connection {str(connection)}"
            )
            connection.recieve(axframe)
            self._connections[connection.connection_id] = connection
            listener.incoming_callback(connection)
            loop = asyncio.get_running_loop()
            loop.create_task(connection.start())
        else:
            self._logger.debug(f"Ignoring frame {str(axframe.address_field)}")

    def start(self) -> None:
        self._logger.info("Start requested. Starting handling loop")
        loop = asyncio.get_event_loop()
        loop.create_task(self.handling_loop())

    def stop(self, abort=False):
        if abort:
            self._logger.warn("Abort requested. Aborting all connections.")
            for connection in self._connections.values():
                connection.stop(abort=True)
            self._active = False
        else:
            self._logger.info("Stop requested")
            self._shutdown_requested = True

    async def handling_loop(self):
        while self._active:
            for connection in self._connections.values():
                if not connection.active:
                    self._logger.debug(
                        f"Destroying inactive connection {str(connection)}"
                    )
                    self._connections.pop(connection.connection_id)
                    del connection
            gc.collect()
            if self._shutdown_requested:
                for connection in self._connections.values():
                    if (
                        connection.connection_state != AX25ConnectionState.AWAITING_RELEASE
                    ):
                        self._logger.debug(
                            f"Requesting graceful shutdown of connection {str(connection)}"
                        )
                        connection.stop()
                if len(self._connections.items()) == 0:
                    self._logger.info("Graceful shutdown complete.")
                    return
            await asyncio.sleep(5)
