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

import time

def get_time_ms() -> int:
    """Get current system time since epoch in milliseconds

    Returns:
        int: Current system time in milliseconds
    """    
    return int(time.monotonic_ns() / 1000000)

def get_time() -> int:
    """Get current system time since epoch in seconds

    Returns:
        int: Current system time since epoch in seconds
    """    
    return int(time.monotonic_ns() / 1000000000)