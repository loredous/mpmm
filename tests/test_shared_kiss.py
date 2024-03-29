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

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


from shared.kiss import KISSFrame, KISSCommand  # noqa: E402


def test_simple_decode():
    # Arrange
    test_frame = bytes([0xC0, 0x00, 0x54, 0x45, 0x53, 0x54, 0xC0])
    expected_port = 0
    expected_command = KISSCommand.DATA_FRAME
    expected_data = b"TEST"

    # Act
    frame = KISSFrame.decode(test_frame)

    # Assert
    assert isinstance(frame, list)
    assert isinstance(frame[0], KISSFrame)
    assert frame[0].port == expected_port
    assert frame[0].command == expected_command
    assert frame[0].data == expected_data


def test_complex_decode():
    # Arrange
    test_frame = bytes([0xC0, 0x00, 0x54, 0xDB, 0xDC, 0x45, 0x53, 0xDB, 0xDD, 0x54, 0xC0])
    expected_port = 0
    expected_command = KISSCommand.DATA_FRAME
    expected_data = bytes([0x54, 0xC0, 0x45, 0x53, 0xDB, 0x54])

    # Act
    frame = KISSFrame.decode(test_frame)

    # Assert
    assert isinstance(frame, list)
    assert isinstance(frame[0], KISSFrame)
    assert frame[0].port == expected_port
    assert frame[0].command == expected_command
    assert frame[0].data == expected_data


def test_decode_multiple_frames():
    # Arrange
    test_frame = bytes([0xC0, 0x00, 0x54, 0x45, 0x53, 0x54, 0xC0, 0xC0, 0x00, 0x54, 0xDB, 0xDC, 0x45, 0x53, 0xDB, 0xDD, 0x54, 0xC0])
    expected_port_1 = 0
    expected_command_1 = KISSCommand.DATA_FRAME
    expected_data_1 = b"TEST"
    expected_port_2 = 0
    expected_command_2 = KISSCommand.DATA_FRAME
    expected_data_2 = bytes([0x54, 0xC0, 0x45, 0x53, 0xDB, 0x54])

    # Act
    frame = KISSFrame.decode(test_frame)

    # Assert
    assert isinstance(frame, list)
    assert len(frame) == 2
    assert isinstance(frame[0], KISSFrame)
    assert frame[0].port == expected_port_1
    assert frame[0].command == expected_command_1
    assert frame[0].data == expected_data_1
    assert isinstance(frame[1], KISSFrame)
    assert frame[1].port == expected_port_2
    assert frame[1].command == expected_command_2
    assert frame[1].data == expected_data_2


def test_simple_encode():
    # Arrange
    port = 0
    command = KISSCommand.DATA_FRAME
    data = [0x54, 0x45, 0x53, 0xDB, 0x54]
    frame_object = KISSFrame(port=port, command=command, data=bytes(data))
    expected_frame = [0xC0, 0x00, 0x54, 0x45, 0x53, 0xDB, 0xDD, 0x54, 0xC0]

    # Act
    result = frame_object.encode()

    # Assert
    assert isinstance(result, bytes)
    assert result == bytes(expected_frame)


def test_complex_encode():
    # Arrange
    port = 0
    command = KISSCommand.DATA_FRAME
    data = [0x54, 0xC0, 0x45, 0x53, 0xDB, 0x54]
    frame_object = KISSFrame(port=port, command=command, data=bytes(data))
    expected_frame = [0xC0, 0x00, 0x54, 0xDB, 0xDC, 0x45, 0x53, 0xDB, 0xDD, 0x54, 0xC0]

    # Act
    result = frame_object.encode()

    # Assert
    assert isinstance(result, bytes)
    assert result == bytes(expected_frame)
