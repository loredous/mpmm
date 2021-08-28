from shared.models.message import MessageType
from typing import List
from pydantic import BaseModel
from enum import Enum
from shared.models.interface import Interface

class RemoteType(Enum):
    BBS = 1

class Remote(BaseModel):
    name: str
    callsign: str
    type: RemoteType
    priority: int = 0
    reachable_via: List[Interface]
    can_handle: List[MessageType]