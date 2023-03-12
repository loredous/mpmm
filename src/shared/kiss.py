from enum import Enum
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
