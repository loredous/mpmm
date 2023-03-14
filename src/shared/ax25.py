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
from typing import List, Optional, Self, Tuple

from pydantic import BaseModel
from utils import chunk


class AX25PID(Enum):
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
        pass


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
            case 0:
                frame_type, sequence, receive = cls.decode_iframe_control(field_bytes, modulo)
                length = modulo.value
            case 2:
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

    @staticmethod
    def decode_iframe_control(field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> Tuple[AX25FrameType, int, int]:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        frame_type = AX25FrameType.I_FRAME
        sequence = int((field_bytes[0] & 6) >> 1)
        response = int((field_bytes[0] & 224) >> 5)
        return (frame_type, sequence, response)

    @staticmethod
    def decode_sframe_control(field_bytes: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8) -> Tuple[AX25FrameType, int]:
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        frame_type = AX25FrameType.I_FRAME
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
    information: Optional[bytes]

    @classmethod
    def decode(cls, frame_data: bytes, modulo: AX25Modulo = AX25Modulo.MOD_8):
        if modulo == AX25Modulo.MOD_128:
            raise NotImplementedError('MOD128 frames are not currently supported')
        addr_field = cls.decode_address_field(frame_data)
        control_field = cls.decode_control_field(frame=frame_data, offset=addr_field.length, modulo=modulo)
        pid = None
        offset = addr_field.length + control_field.length
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
        frame_data = []
        frame_data += self.address_field.encode()
        frame_data += self.control_field.encode(self.modulo)
        if self.pid:
            frame_data += bytes(self.pid.value)
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


if __name__ == "__main__":
    print(AX25Frame.decode(b'\x82\xa0\x9a\x92`l`\x9c`\x82\xaa\xb0@b\xae\x92\x88\x8ad@e\x03\xf0@121758z3915.89NI10506.85W#PHG5130/Devils Head Digi/I-Gate14.0V,16.5C/61.7F/A=009150'))
    # N0AUX-1>APMI06,WIDE2-2
