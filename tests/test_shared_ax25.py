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
import base64

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


from shared.ax25 import AX25AddressField, AX25ControlField, AX25Frame, AX25Address  # noqa: E402


def test_entire_frame_decode_encode():
    # Arrange
    FRAME_DATA = base64.b64decode('qKJgsqyuYK6Ebo6kQPKcbpSUskDwrmCqoKZA/q6SiIpkQOED8GBwSyhuSWlrL2AiSDF9TGlzdGVuaW5nIG9uIDQ0OS4zMDAgLSB3YjdnckBhcnJsLm5ldF8lDQ==')
    EXPECTED_FRAME = AX25Frame.parse_raw('{"modulo": 1, "address_field": {"source": {"callsign": "WB7GR", "ssid": "9", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, "destination": {"callsign": "TQ0YVW", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": false}, "path": [{"callsign": "N7JJY", "ssid": "8", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, {"callsign": "W0UPS", "ssid": "15", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, {"callsign": "WIDE2", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}], "length": 35}, "control_field": {"frame_type": 8196, "length": 1, "poll_final": false, "sequence": null, "receive": null}, "pid": 240, "information": "`pK(nIik/`\\"H1}Listening on 449.300 - wb7gr@arrl.net_%\\r"}')

    # Act
    decoded_frame = AX25Frame.decode(FRAME_DATA)
    encoded_bytes = decoded_frame.encode()

    # Assert
    assert decoded_frame == EXPECTED_FRAME
    assert encoded_bytes == FRAME_DATA


def test_address_encode_decode():
    # Arrange
    BYTE_DATA = base64.b64decode('qKJgsqyuYA==')
    EXPECTED_ADDRESS = AX25Address.parse_raw('{"callsign": "TQ0YVW", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": false}')

    # Act
    addr = AX25Address.decode(BYTE_DATA)
    encoded_bytes = addr.encode()

    # Assert
    assert addr == EXPECTED_ADDRESS
    assert encoded_bytes == BYTE_DATA


def test_address_field_encode_decode():
    # Arrange
    BYTE_DATA = base64.b64decode('qKJgsqyuYK6Ebo6kQPKcbpSUskDwrmCqoKZA/q6SiIpkQOE=')
    EXPECTED_ADDRESS_FIELD = AX25AddressField.parse_raw('{"source": {"callsign": "WB7GR", "ssid": "9", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, "destination": {"callsign": "TQ0YVW", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": false}, "path": [{"callsign": "N7JJY", "ssid": "8", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, {"callsign": "W0UPS", "ssid": "15", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, {"callsign": "WIDE2", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}], "length": 35}')

    # Act
    addr = AX25AddressField.decode(BYTE_DATA)
    encoded_bytes = addr.encode()

    # Assert
    assert addr == EXPECTED_ADDRESS_FIELD
    assert encoded_bytes == BYTE_DATA


def test_control_field_encode_decode_uframe():
    # Arrange
    BYTE_DATA = b'\x03'
    EXPECTED_CONTROL_FIELD = AX25ControlField.parse_raw('{"frame_type": 8196, "length": 1, "poll_final": false, "sequence": null, "receive": null}')

    # Act
    ctrl = AX25ControlField.decode(BYTE_DATA)
    encoded_bytes = ctrl.encode()

    # Assert
    assert ctrl == EXPECTED_CONTROL_FIELD
    assert encoded_bytes == BYTE_DATA


def test_control_field_encode_decode_iframe():
    # Arrange
    BYTE_DATA = b'\xDC'
    EXPECTED_CONTROL_FIELD = AX25ControlField.parse_raw('{"frame_type": 1, "length": 1, "poll_final": true, "sequence": 6, "receive": 6}')

    # Act
    ctrl = AX25ControlField.decode(BYTE_DATA)
    encoded_bytes = ctrl.encode()

    # Assert
    assert ctrl == EXPECTED_CONTROL_FIELD
    assert encoded_bytes == BYTE_DATA


def test_control_field_encode_decode_sframe():
    # Arrange
    BYTE_DATA = b'\xD9'
    EXPECTED_CONTROL_FIELD = AX25ControlField.parse_raw('{"frame_type": 34, "length": 1, "poll_final": true, "sequence": null, "receive": 6}')

    # Act
    ctrl = AX25ControlField.decode(BYTE_DATA)
    encoded_bytes = ctrl.encode()

    # Assert
    assert ctrl == EXPECTED_CONTROL_FIELD
    assert encoded_bytes == BYTE_DATA
