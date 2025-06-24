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

import base64
from hypothesis import given, note, strategies as st

from ax25.frame import AX25PID, AX25AddressField, AX25ControlField, AX25Frame, AX25Address, AX25FrameType, AX25Modulo




def test_entire_frame_decode_encode():
    # Arrange
    FRAME_DATA = base64.b64decode('qKJgsqyuYK6Ebo6kQPKcbpSUskDwrmCqoKZA/q6SiIpkQOED8GBwSyhuSWlrL2AiSDF9TGlzdGVuaW5nIG9uIDQ0OS4zMDAgLSB3YjdnckBhcnJsLm5ldF8lDQ==')
    EXPECTED_ADDRESS_FIELD = AX25AddressField(
        source=AX25Address(callsign="WB7GR", ssid="9", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True),
        destination=AX25Address(callsign="TQ0YVW", ssid="0", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=False),
        path=[
            AX25Address(callsign="N7JJY", ssid="8", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True),
            AX25Address(callsign="W0UPS", ssid="15", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True),
            AX25Address(callsign="WIDE2", ssid="0", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True)
        ],
        length=35
    )
    EXPECTED_CONTROL_FIELD = AX25ControlField(
        frame_type = AX25FrameType(8196),
        poll_final = False,
        sequence = None,
        receive = None,
        length = 1
    )
    EXPECTED_FRAME = AX25Frame(
        modulo=AX25Modulo.MOD_8,
        address_field=EXPECTED_ADDRESS_FIELD,
        control_field=EXPECTED_CONTROL_FIELD,
        pid=AX25PID(240),
        information=b'`pK(nIik/`"H1}Listening on 449.300 - wb7gr@arrl.net_%\r'
    )

    # Act
    decoded_frame = AX25Frame.decode(FRAME_DATA)
    encoded_bytes = decoded_frame.encode()

    # Assert
    assert decoded_frame == EXPECTED_FRAME
    assert encoded_bytes == FRAME_DATA


def test_address_encode_decode():
    # Arrange
    BYTE_DATA = base64.b64decode('qKJgsqyuYA==')
    EXPECTED_ADDRESS = AX25Address(callsign="TQ0YVW", ssid="0", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=False)

    # Act
    addr = AX25Address.decode(BYTE_DATA)
    encoded_bytes = addr.encode()

    # Assert
    assert addr == EXPECTED_ADDRESS
    assert encoded_bytes == BYTE_DATA


def test_address_field_encode_decode():
    # Arrange
    BYTE_DATA = base64.b64decode('qKJgsqyuYK6Ebo6kQPKcbpSUskDwrmCqoKZA/q6SiIpkQOE=')
    EXPECTED_ADDRESS_FIELD = AX25AddressField(
        source=AX25Address(callsign="WB7GR", ssid="9", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True),
        destination=AX25Address(callsign="TQ0YVW", ssid="0", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=False),
        path=[
            AX25Address(callsign="N7JJY", ssid="8", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True),
            AX25Address(callsign="W0UPS", ssid="15", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True),
            AX25Address(callsign="WIDE2", ssid="0", reserved_bit_5=True, reserved_bit_6=True, command_repeat_bit=True)
        ],
        length=35
    )

    # Act
    addr = AX25AddressField.decode(BYTE_DATA)
    encoded_bytes = addr.encode()

    # Assert
    assert addr == EXPECTED_ADDRESS_FIELD
    assert encoded_bytes == BYTE_DATA


def test_control_field_encode_decode_uframe():
    # Arrange
    BYTE_DATA = b'\x03'
    EXPECTED_CONTROL_FIELD = AX25ControlField(frame_type=AX25FrameType(8196), length=1, poll_final=False, sequence=None, receive=None)
    

    # Act
    ctrl = AX25ControlField.decode(BYTE_DATA)
    encoded_bytes = ctrl.encode()

    # Assert
    assert ctrl == EXPECTED_CONTROL_FIELD
    assert encoded_bytes == BYTE_DATA


def test_control_field_encode_decode_iframe():
    # Arrange
    BYTE_DATA = b'\xDC'
    EXPECTED_CONTROL_FIELD = AX25ControlField(frame_type=AX25FrameType(1), length=1, poll_final=True, sequence=6, receive=6)

    # Act
    ctrl = AX25ControlField.decode(BYTE_DATA)
    encoded_bytes = ctrl.encode()

    # Assert
    assert ctrl == EXPECTED_CONTROL_FIELD
    assert encoded_bytes == BYTE_DATA


def test_control_field_encode_decode_sframe():
    # Arrange
    BYTE_DATA = b'\xD9'
    EXPECTED_CONTROL_FIELD = AX25ControlField(frame_type=AX25FrameType(34), length=1, poll_final=True, sequence=None, receive=6)

    # Act
    ctrl = AX25ControlField.decode(BYTE_DATA)
    encoded_bytes = ctrl.encode()

    # Assert
    assert ctrl == EXPECTED_CONTROL_FIELD
    assert encoded_bytes == BYTE_DATA

@given(callsign=st.text(min_size=4, max_size=6,alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), ssid=st.integers(min_value=0, max_value=15), reserved_bit_5=st.booleans(), reserved_bit_6=st.booleans(), command_repeat_bit=st.booleans())
def test_address_property_encode_decode(callsign, ssid, reserved_bit_5, reserved_bit_6, command_repeat_bit):
    # Arrange
    addr = AX25Address(callsign=callsign, ssid=str(ssid), reserved_bit_5=reserved_bit_5, reserved_bit_6=reserved_bit_6, command_repeat_bit=command_repeat_bit)
    encoded = addr.encode()
    decoded = AX25Address.decode(encoded)

    assert addr == decoded

@st.composite
def generate_address(draw):
    callsign = draw(st.text(min_size=4, max_size=6, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'))
    ssid = draw(st.integers(min_value=0, max_value=15))
    reserved_bit_5 = draw(st.booleans())
    reserved_bit_6 = draw(st.booleans())
    command_repeat_bit = draw(st.booleans())
    return AX25Address(callsign=callsign, ssid=str(ssid), reserved_bit_5=reserved_bit_5, reserved_bit_6=reserved_bit_6, command_repeat_bit=command_repeat_bit)

@given(source=generate_address(), dest=generate_address(), pathlen=st.integers(min_value=0, max_value=4), path=st.lists(generate_address(), min_size=0, max_size=4))
def test_address_field_property_encode_decode(source, dest, pathlen, path):
    # Arrange
    addr_field = AX25AddressField(source=source, destination=dest, path=path)
    encoded = addr_field.encode()
    decoded = AX25AddressField.decode(encoded)
    addr_field.length = decoded.length

    assert addr_field == decoded

@given(poll_final=st.booleans(), sequence=st.integers(min_value=0, max_value=7), receive=st.integers(min_value=0, max_value=7))
def test_control_field_property_encode_decode_IFRAME(poll_final, sequence, receive):
    # Arrange
    ctrl = AX25ControlField(frame_type=AX25FrameType.I_FRAME, poll_final=poll_final, sequence=sequence, receive=receive)
    encoded = ctrl.encode()
    note(f"Encoded: {encoded}")
    decoded = AX25ControlField.decode(encoded)
    ctrl.length = decoded.length
    assert ctrl == decoded