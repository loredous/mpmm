from shared.models.remote import Remote
from shared.models.operator import Operator
from shared.models.interface import Interface
from shared.models.message import Message
from typing import List
from pydantic import BaseModel

class Station(BaseModel):
    callsign: str
    location: str
    locator: str
    interfaces: List[Interface]
    operators: List[Operator]
    remotes: List[Remote]
    messages: List[Message]