
from enum import Enum, Flag
from dataclasses import dataclass, field
from typing import List, Optional, Self, Tuple, Union
from ax25.utils import chunk
from kiss.frame import KISSFrame

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


@dataclass
class AX25Address():
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
        ssid = str((address_bytes[6] & 30) >> 1)
        rb5 = bool((address_bytes[6] & 32))
        rb6 = bool((address_bytes[6] & 64))
        crb = bool((address_bytes[6] & 128))
        return cls(
            callsign=callsign,
            ssid=ssid,
            reserved_bit_5=rb5,
            reserved_bit_6=rb6,
            command_repeat_bit=crb,
        )

    def encode(self):
        address_bytes = []
        address_bytes += self.callsign.encode("utf-8")
        address_bytes += [32] * (6 - len(address_bytes))  # Pad with spaces!
        for index in range(0, len(address_bytes)):
            address_bytes[index] = address_bytes[index] << 1
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
        if self.ssid != "0":
            address = f"{self.callsign}-{self.ssid}"
        else:
            address = self.callsign
        if self.command_repeat_bit:
            address += "*"
        return address

    @property
    def call_with_ssid(self):
        return f"{self.callsign}-{self.ssid}"

    @classmethod
    def from_callsign(cls, callsign: str) -> Self:
        if "-" in callsign:
            components = callsign.split("-")
            call = components[0]
            ssid = components[1]
        else:
            call = callsign
            ssid = "0"
        return cls(callsign=call, ssid=ssid)


@dataclass
class AX25AddressField():
    source: AX25Address
    destination: AX25Address
    path: List[AX25Address] = field(default_factory=list)
    length: Optional[int] = 0

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
            length=len(address_bytes),
        )

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
            return f"{self.source.call_with_ssid}->{self.destination.call_with_ssid}"

    def get_response_field(self) -> Self:
        response_field = AX25AddressField(
            source=self.destination,
            destination=self.source,
            path=self.path[::-1],
            length=self.length,
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
    UNSPECIFIED = 0
    MOD_8 = 1
    MOD_128 = 2


@dataclass
class AX25ControlField():
    frame_type: AX25FrameType
    poll_final: bool
    length: Optional[int] = 0
    sequence: Optional[int] = 0
    receive: Optional[int] = 0

    @classmethod
    def decode(cls, field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> Self:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError("MOD128 frames are not currently supported")
        match field_bytes[0] & 3:
            case 0 | 2:
                frame_type, sequence, receive = cls.decode_iframe_control(
                    field_bytes, modulo
                )
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
            receive=receive,
        )

    def encode(self, modulo: AX25Modulo = AX25Modulo.MOD_8):
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError("MOD128 frames are not currently supported")
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
    def decode_iframe_control(
        field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8
    ) -> Tuple[AX25FrameType, int, int]:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError("MOD128 frames are not currently supported")
        frame_type = AX25FrameType.I_FRAME
        sequence = int((field_bytes[0] & 14) >> 1)
        response = int((field_bytes[0] & 224) >> 5)
        return (frame_type, sequence, response)

    @staticmethod
    def decode_sframe_control(
        field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8
    ) -> Tuple[AX25FrameType, int]:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError("MOD128 frames are not currently supported")
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
    def decode_uframe_control(
        field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8
    ) -> AX25FrameType:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError("MOD128 frames are not currently supported")
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


@dataclass
class AX25Frame():
    address_field: AX25AddressField
    control_field: AX25ControlField
    pid: Optional[AX25PID]
    modulo: AX25Modulo = AX25Modulo.MOD_8
    information: Optional[bytes] = None

    @classmethod
    def decode(
        cls, frame: Union[bytes, KISSFrame], modulo: AX25Modulo = AX25Modulo.MOD_8
    ):
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError("MOD128 frames are not currently supported")
        if isinstance(frame, bytes):
            frame_data = frame
        elif isinstance(frame, KISSFrame):
            frame_data = frame.data
        else:
            raise RuntimeError(
                "Invalid data type for frame. Expected bytes or KISSFrame"
            )
        addr_field = cls.decode_address_field(frame_data)
        control_field = cls.decode_control_field(
            frame=frame_data, offset=addr_field.length, modulo=modulo
        )
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
            information=bytes(information),
        )

    def encode(self) -> bytes:
        frame_data = b""
        frame_data += self.address_field.encode()
        frame_data += self.control_field.encode(self.modulo)
        if self.pid:
            frame_data += self.pid.value.to_bytes()
        if self.information:
            frame_data += bytes(self.information)
        return frame_data

    @staticmethod
    def decode_control_field(
        frame: bytes, offset: int, modulo: AX25Modulo = AX25Modulo.MOD_8
    ):
        return AX25ControlField.decode(frame[offset: (offset + modulo.value)])

    @staticmethod
    def decode_address_field(frame: bytes) -> AX25AddressField:
        address_field = []
        for byte in frame:
            address_field.append(byte)
            if byte & 1 == 1:
                break
        return AX25AddressField.decode(bytes(address_field))


class AX25FrameFactory:
    @staticmethod
    def dm_response(axframe: AX25Frame, poll_final: bool = False):
        addr = axframe.address_field.get_response_field()
        control = AX25ControlField(
            frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_DM,
            poll_final=poll_final,
        )
        frame = AX25Frame(address_field=addr, control_field=control, pid=AX25PID.NONE)
        return frame

    @staticmethod
    def ua_response(axframe: AX25Frame, poll_final: bool = False):
        addr = axframe.address_field.get_response_field()
        control = AX25ControlField(
            frame_type=AX25FrameType.U_FRAME | AX25FrameType.UNN_UA,
            poll_final=poll_final,
        )
        frame = AX25Frame(address_field=addr, control_field=control, pid=AX25PID.NONE)
        return frame
    
    @staticmethod
    def disc(local_call: str, remote_call: str, poll_final: bool = True):
        local = AX25Address.from_callsign(local_call)
        remote = AX25Address.from_callsign(remote_call)
        addr = AX25AddressField(
            source=local,
            destination=remote
        )
        control = AX25ControlField(
            AX25FrameType = AX25FrameType.U_FRAME | AX25FrameType.UNN_DISC,
            poll_final=poll_final
        )
        frame = AX25Frame(address_field=addr, control_field=control, pid=AX25PID.NONE)
