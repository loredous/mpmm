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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from shared.utils import  *

def test_chunk_util():
    # Arrange
    CHUNK_LENGTH = 3
    TEST_LIST = [1,2,3,4,5,6,7,8,9,10]
    EXPECTED_CHUNKS = [
        [1,2,3],
        [4,5,6],
        [7,8,9],
        [10]
    ]
    
    # Act
    result = chunk(TEST_LIST, CHUNK_LENGTH)

    # Assert
    assert isinstance(result,Iterator)
    for result_expected in zip(result,EXPECTED_CHUNKS):
        assert len(result[0]) <= CHUNK_LENGTH
        assert result[0] == result[1]


@mock.patch("shared.utils.time.monotonic_ns")
def test_get_time_ms(MOCK_TIME):
    # Arrange
    MOCK_TIME.return_value = 108967125000000
    EXPECTED_RESULT = 108967125

    # Act
    result = get_time_ms()

    # Assert
    assert isinstance(result,int)
    assert result == EXPECTED_RESULT

@mock.patch("shared.utils.time.monotonic_ns")
def test_get_time(MOCK_TIME):
    # Arrange
    MOCK_TIME.return_value = 108967125000000
    EXPECTED_RESULT = 108967

    # Act
    result = get_time()

    # Assert
    assert isinstance(result,int)
    assert result == EXPECTED_RESULT