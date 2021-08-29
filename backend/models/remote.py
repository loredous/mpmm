from typing import List
from pydantic import BaseModel
from models.interface import Interface
from models.enums import RemoteType, MessageType



class Remote(BaseModel):
    name: str
    callsign: str
    type: RemoteType
    priority: int = 0
    reachable_via: List[Interface]
    can_handle: List[MessageType]