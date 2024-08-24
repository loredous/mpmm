from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Coroutine, Optional
from asyncio import AbstractEventLoop, get_running_loop, Task
from queue import Queue

from mpmm_ax25.ax25_frame import AX25Address, AX25Frame, AX25FrameFactory, AX25FrameType, AX25Modulo
from mpmm_ax25.timer import Timer, TimerResult, TimerState

from logging import Logger, getLogger


class AX25ConnectionState(Enum):
    DISCONNECTED = 0
    AWAITING_CONNECTION = 1
    AWAITING_RELEASE = 2
    CONNECTED = 3
    TIMER_RECOVERY = 4


@dataclass
class AX25Connection:
    local_address: AX25Address # Local Address of this connection

    state: AX25ConnectionState = field(default=AX25ConnectionState.DISCONNECTED, init=False) # Current Connection State
    remote_address: Optional[AX25Address] = None # Remote Address for this connection, if none then we are awaiting a connection or UI data
    modulo: AX25Modulo = AX25Modulo.UNSPECIFIED # Modulo for this connection
    i_frame_timeout: float = 10.0 # I-Frame Timeout in seconds
    keepalive_timeout: float = 30.0 # Keepalive Timeout in seconds
    outgoing_frames: Queue[AX25Frame] = field(default_factory=Queue) # Queue of outgoing frames
    _ui_handlers: list[Coroutine[AX25Frame, None, None]] = field(default_factory=list) # List of UI Frame Handlers  
    peer_busy: bool = False # Peer Busy State

    ## Sequence Tracking Data
    sequence_number: int = 0 # Send State Variable - V(S)
    receive_sequence_number: int = 0 # Receive State Variable - V(R)
    ack_sequence_number: int = 0 # Acknowledge State Variable - V(A)

    ## Timers
    _outstanding_i_frame_timer: Timer = field(default=None,init=False) # Timer for outstanding I-Frames - T1
    _keepalive_timer: Timer = field(default=None,init=False) # Timer for Keepalive - T3

    ## Logging
    logger: Logger = getLogger(__name__)

    def __str__(self) -> str:
        return f"AX25Connection: {self.local_address} -> {self.remote_address} [State: {self.state}] (S: {self.sequence_number}, R: {self.receive_sequence_number}, A: {self.ack_sequence_number})"


    def __post_init__(self):
        self._outstanding_i_frame_timer = Timer(self._on_outstanding_i_frame_timeout, timeout=self.i_frame_timeout)
        self._keepalive_timer = Timer(self._on_keepalive_timeout, timeout=self.keepalive_timeout)
        self._reset_state()
        self.logger.info(f"AX25 Connection Initialized: {self}")

    async def _on_outstanding_i_frame_timeout(self, timer: Timer, result: TimerResult):
        self.logger.debug(f"Outstanding I-Frame Timer Stopped: {result.value}")

    async def _on_keepalive_timeout(self, timer: Timer, result: TimerResult):
        self.logger.debug(f"Keepalive Timer Stopped: {result.value}")

    def _reset_state(self, discard_outgoing_frames: bool = True):
        if self._outstanding_i_frame_timer.state == TimerState.RUNNING:
            self._outstanding_i_frame_timer.stop()
        if self._keepalive_timer.state == TimerState.RUNNING:
            self._keepalive_timer.stop()
        if discard_outgoing_frames:
            self.outgoing_frames = Queue()
        self.sequence_number = 0
        self.receive_sequence_number = 0
        self.ack_sequence_number = 0
        self.logger.debug("Connection State Reset")

    

    async def handle_ax25_frame(self, frame: AX25Frame):
        """
        Handle an incoming AX.25 Frame

        Assumptions: Frames are either addressed to this connection's local address or are UI Frames
        """
        self.logger.debug(f"Handling Frame: {frame}")
        match self.state:
            case AX25ConnectionState.DISCONNECTED:
                await self.disconnected_frame_handler(frame)
            case AX25ConnectionState.AWAITING_CONNECTION:
                await self.awaiting_connection_frame_handler(frame)
            case AX25ConnectionState.AWAITING_RELEASE:
                await self.awaiting_release_frame_handler(frame)
            case AX25ConnectionState.CONNECTED:
                await self.connected_frame_handler(frame)
            case AX25ConnectionState.TIMER_RECOVERY:
                await self.timer_recovery_frame_handler(frame)

    async def send_ax25_frame(self, frame: AX25Frame):
        self.outgoing_frames.put(frame)

    def add_ui_handler(self, handler: Coroutine[AX25Frame, None, None]):
        self._ui_handlers.append(handler)

    def remove_ui_handler(self, handler: Coroutine[AX25Frame, None, None]):
        self._ui_handlers.remove(handler)

    async def handle_ui_frame(self, frame: AX25Frame):
        for handler in self._ui_handlers:
            await handler(frame)

    async def disconnected_frame_handler(self, frame: AX25Frame):
        if frame.control_field.frame_type == AX25FrameType.UNN_SABM|AX25FrameType.U_FRAME:
                if self.modulo != AX25Modulo.MOD_128:
                    self.modulo = AX25Modulo.MOD_8
                    self.remote_address = frame.address_field.source
                    self._reset_state()
                    await self._keepalive_timer.start()
                    await self.send_ax25_frame(AX25FrameFactory.ua_response(frame, poll_final=frame.control_field.poll_final))
                    self.state = AX25ConnectionState.CONNECTED
                else:
                    await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_SABME|AX25FrameType.U_FRAME:
                if self.modulo != AX25Modulo.MOD_8:
                    self.modulo = AX25Modulo.MOD_128
                    self.remote_address = frame.address_field.source
                    self._reset_state()
                    await self._keepalive_timer.start()
                    await self.send_ax25_frame(AX25FrameFactory.ua_response(frame, poll_final=frame.control_field.poll_final))
                    self.state = AX25ConnectionState.CONNECTED
                else:
                    await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_UI|AX25FrameType.U_FRAME:
            await self.handle_ui_frame(frame)
            if frame.control_field.poll_final:
                await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=True))
        elif frame.control_field.frame_type == AX25FrameType.UNN_DISC|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=frame.control_field.poll_final))
        else:
            self.logger.debug(f"Ignoring Frame in Disconnected State: {frame}")

    async def awaiting_connection_frame_handler(self, frame: AX25Frame):
        if frame.control_field.frame_type == AX25FrameType.UNN_SABM|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.ua_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_SABME|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_DISC|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_UI|AX25FrameType.U_FRAME:
            await self.handle_ui_frame(frame)
            if frame.control_field.poll_final:
                await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=True))
        elif frame.control_field.frame_type == AX25FrameType.UNN_DM|AX25FrameType.U_FRAME:
            if frame.control_field.poll_final:
                self._reset_state()
                self.state = AX25ConnectionState.DISCONNECTED
        elif frame.control_field.frame_type == AX25FrameType.UNN_UA|AX25FrameType.U_FRAME:
            if frame.control_field.poll_final:
                self.remote_address = frame.address_field.source
                self._reset_state()
                self.state = AX25ConnectionState.CONNECTED
            
    async def awaiting_release_frame_handler(self, frame: AX25Frame):
        if frame.control_field.frame_type == AX25FrameType.UNN_SABM|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_DISC|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.ua_response(frame, poll_final=frame.control_field.poll_final))
        elif frame.control_field.frame_type == AX25FrameType.UNN_UI|AX25FrameType.U_FRAME:
            await self.handle_ui_frame(frame)
            if frame.control_field.poll_final:
                await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=True))
        elif frame.control_field.frame_type & AX25FrameType.S_FRAME:
            if frame.control_field.poll_final:
                await self.send_ax25_frame(AX25FrameFactory.dm_response(frame, poll_final=True))
        elif frame.control_field.frame_type == AX25FrameType.UNN_UA|AX25FrameType.U_FRAME:
            if frame.control_field.poll_final:
                self._reset_state()
                self.state = AX25ConnectionState.DISCONNECTED
        elif frame.control_field.frame_type == AX25FrameType.UNN_DM|AX25FrameType.U_FRAME:
            if frame.control_field.poll_final:
                self._reset_state()
                self.state = AX25ConnectionState.DISCONNECTED

    async def connected_frame_handler(self, frame: AX25Frame):
        if frame.control_field.frame_type == AX25FrameType.UNN_UI|AX25FrameType.U_FRAME:
            await self.handle_ui_frame(frame)
        elif frame.control_field.frame_type == AX25FrameType.UNN_DISC|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.ua_response(frame, poll_final=frame.control_field.poll_final))
            self._reset_state()
            self.state = AX25ConnectionState.DISCONNECTED
        elif frame.control_field.frame_type == AX25FrameType.UNN_SABM|AX25FrameType.U_FRAME or frame.control_field.frame_type == AX25FrameType.UNN_SABME|AX25FrameType.U_FRAME:
            await self.send_ax25_frame(AX25FrameFactory.ua_response(frame, poll_final=frame.control_field.poll_final))
            self._reset_state(discard_outgoing_frames=self.sequence_number != self.ack_sequence_number)
            self._keepalive_timer.start()
        elif frame.control_field.frame_type == AX25FrameType.UNN_UA|AX25FrameType.U_FRAME:
            self.state = AX25ConnectionState.AWAITING_CONNECTION
        elif frame.control_field.frame_type == AX25FrameType.UNN_DM|AX25FrameType.U_FRAME:
            self._reset_state()
            self.state = AX25ConnectionState.DISCONNECTED
        elif frame.control_field.frame_type ==  AX25FrameType.UNN_FRMR|AX25FrameType.U_FRAME:
            self.state = AX25ConnectionState.AWAITING_CONNECTION
        elif frame.control_field.frame_type == AX25FrameType.SUP_RR|AX25FrameType.S_FRAME:
            self.peer_busy = False
        elif frame.control_field.frame_type == AX25FrameType.SUP_RNR|AX25FrameType.S_FRAME:
            self.peer_busy = True
        else:
            self.logger.debug(f"Ignoring Frame in Connected State: {frame}")

    async def timer_recovery_frame_handler(self, frame: AX25Frame):
        pass

