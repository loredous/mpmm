from models.remote import Remote
from models.operator import Operator
from models.interface import Interface
from models.message import Message
from typing import List
from pydantic import BaseModel


class Station(BaseModel):
    callsign: str
    location: str
    locator: str
    interfaces: List[Interface] = []
    operators: List[Operator] = []
    remotes: List[Remote] = []
    messages: List[Message] = []
