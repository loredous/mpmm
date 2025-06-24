from dataclasses import dataclass
from enum import Enum
from typing import List, Self

class KISSCommand(Enum):
    """Enum of KISS Command types"""    
    DATA_FRAME = 0
    TX_DELAY = 1
    PERSISTENCE = 2
    SLOT_TIME = 3
    TX_TAIL = 4
    FULL_DUPLEX = 5
    SET_HARDWARE = 6
    RETURN = 255


class KISSCode(Enum):
    """KISS special frame markers"""
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD

@dataclass
class KISSFrame():
    """
    Model representing a single KISS frame

    Args:
        data (bytes): Data field of KISS frame
        command (KISSCommand): Frame type identifier
        port (int): KISS TNC port associated with this frame
    """
    data: bytes
    command: KISSCommand
    port: int

    
    def __post_init__(self):
        """
        Validate items that require validation
        """
        self.is_valid_port(self.port)

    def is_valid_port(cls, v: int) -> int:
        """
        Validate value for KISS port number. Valid port IDs are between 0 and 15 inclusive

        Args:
            v (int): Value to check

        Returns:
            int: Validated KISS port value

        Raises:
            ValueError
        """
        if v < 0 or v > 15:
            raise ValueError("KISS port number must be between 0 and 15 inclusive")
        
    def _escape_byte(self, byte: bytes) -> bytes:
        """
        Escape a byte for KISS frame encoding

        Args:
            byte (int): Byte to escape

        Returns:
            bytes: Escaped byte
        """
        if byte == bytes([KISSCode.FEND.value]):
            return bytes([KISSCode.FESC.value, KISSCode.TFEND.value])
        elif byte == bytes([KISSCode.FESC.value]):
            return bytes([KISSCode.FESC.value, KISSCode.TFESC.value])
        else:
            return byte

    @classmethod
    def _unescape_frame(cls, frame: bytes) -> bytes:
        """
        Unescape a KISS frame

        Args:
            frame (bytes): KISS frame to unescape

        Returns:
            bytes: Unescaped KISS frame
        """
        unescaped_frame = bytearray()
        escaped = False
        for byte in frame:
            if byte == KISSCode.FESC.value:
                escaped = True
                continue
            if escaped:
                if byte == KISSCode.TFEND.value:
                    unescaped_frame.append(KISSCode.FEND.value)
                elif byte == KISSCode.TFESC.value:
                    unescaped_frame.append(KISSCode.FESC.value)
                else:
                    unescaped_frame.append(byte)
                escaped = False
            else:
                unescaped_frame.append(byte)
        return bytes(unescaped_frame)

    def encode(self) -> bytes:
        """
        Get the byte representation of the KISSFrame

        Returns:
            bytes: Raw bytes representing the KISS frame
        """
        # KISS frame starts with FEND
        kiss_frame = bytearray([KISSCode.FEND.value])

        # Add the command and port
        type_indicator = self.command.value | (self.port << 4)
        
        kiss_frame.extend(self._escape_byte(bytes([type_indicator])))

        # Encode each byte of the frame
        for byte in self.data:
                kiss_frame.extend(self._escape_byte(bytes([byte])))

        # End the KISS frame with FEND
        kiss_frame.extend(bytes([KISSCode.FEND.value]))
        return bytes(kiss_frame)

    @classmethod
    def decode(cls, data: bytes) -> List[Self]:
        """
        Decode raw bytes of one or more KISS frames into KISSFrame objects

        Args:
            data (bytes): Raw Bytes representing a KISS frame

        Returns:
            List[Self]: List of KISSFrame objects decoded from bytes
        """
        frames = data.split(bytes([KISSCode.FEND.value]))
        decoded_frames = []
        for frame in frames:
            if frame == b"":
                continue
            unescaped_frame = cls._unescape_frame(frame)
            decoded_type = unescaped_frame[0]
            if decoded_type == KISSCommand.RETURN.value:
                decoded_frames.append(
                cls(
                    data=b'', command=KISSCommand.RETURN, port=0
                )
                )
                continue
            decoded_command = KISSCommand(decoded_type & 0x0F)
            decoded_port = (decoded_type & 0xF0) >> 4
            decoded_data = unescaped_frame[1:]
            decoded_frames.append(
                cls(
                    data=bytes(decoded_data), command=decoded_command, port=decoded_port
                )
            )
        return decoded_frames

