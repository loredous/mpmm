import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import pytest
from shared.kiss import KISSFrame, KISSCommand, KISSCode

def test_simple_decode():
    # Arrange
    test_frame = [0xC0,0x00,0x54,0x45,0x53,0x54,0xC0]
    expected_port = 0
    expected_command = KISSCommand.DATA_FRAME
    expected_data = b'TEST'

    # Act
    frame = KISSFrame.decode(test_frame)

    # Assert
    assert isinstance(frame, KISSFrame)
    assert frame.port == expected_port
    assert frame.command == expected_command
    assert frame.data == expected_data

def test_complex_decode():
    # Arrange
    test_frame = [0xC0,0x00,0x54,0xDB,0xDC,0x45,0x53,0xDB,0xDD,0x54,0xC0]
    expected_port = 0
    expected_command = KISSCommand.DATA_FRAME
    expected_data = [0x54,0xc0,0x45,0x53,0xdb,0x54]

    # Act
    frame = KISSFrame.decode(test_frame)

    # Assert
    assert isinstance(frame, KISSFrame)
    assert frame.port == expected_port
    assert frame.command == expected_command
    assert list(frame.data) == expected_data

def test_decode_extra_fend():
    # Arrange
    test_frame = [0xC0,0x00,0x54,0xC0,0x45,0x53,0x54,0xC0]

    # Act
    with pytest.raises(ValueError) as exc_info:
        frame = KISSFrame.decode(test_frame)

    # Assert
    assert exc_info.typename == "ValueError"

def test_decode_missing_fend():
    # Arrange
    test_frame = [0xC0,0x00,0x54,0x45,0x53,0x54]
    # Act
    with pytest.raises(ValueError) as exc_info:
        frame = KISSFrame.decode(test_frame)

    # Assert
    assert exc_info.typename == "ValueError"

def test_simple_encode():
    # Arrange
    port = 0
    command = KISSCommand.DATA_FRAME
    data = [0x54,0x45,0x53,0xdb,0x54]
    frame_object = KISSFrame(port=port, command=command, data=bytes(data))
    expected_frame = [0xC0,0x00,0x54,0x45,0x53,0xDB,0xDD,0x54,0xC0]

    # Act
    result = frame_object.encode()

    # Assert
    assert isinstance(result,bytes)
    assert result == bytes(expected_frame)

def test_complex_encode():
    # Arrange
    port = 0
    command = KISSCommand.DATA_FRAME
    data = [0x54,0xc0,0x45,0x53,0xdb,0x54]
    frame_object = KISSFrame(port=port, command=command, data=bytes(data))
    expected_frame = [0xC0,0x00,0x54,0xDB,0xDC,0x45,0x53,0xDB,0xDD,0x54,0xC0]

    # Act
    result = frame_object.encode()

    # Assert
    assert isinstance(result,bytes)
    assert result == bytes(expected_frame)