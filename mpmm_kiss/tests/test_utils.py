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
from unittest import mock

from mpmm_kiss.utils import get_time_ms, get_time

@mock.patch("mpmm_kiss.utils.time.monotonic_ns")
def test_get_time_ms(MOCK_TIME):
    # Arrange
    MOCK_TIME.return_value = 108967125000000
    EXPECTED_RESULT = 108967125

    # Act
    result = get_time_ms()

    # Assert
    assert isinstance(result,int)
    assert result == EXPECTED_RESULT

@mock.patch("mpmm_kiss.utils.time.monotonic_ns")
def test_get_time(MOCK_TIME):
    # Arrange
    MOCK_TIME.return_value = 108967125000000
    EXPECTED_RESULT = 108967

    # Act
    result = get_time()

    # Assert
    assert isinstance(result,int)
    assert result == EXPECTED_RESULT