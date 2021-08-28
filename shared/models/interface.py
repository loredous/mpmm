from pydantic import BaseModel
from enum import Enum, Flag

class InterfaceType(Enum):
    KISS_TNC = 0
    TELNET = 1

class InterfaceCapability(Flag):
    RECEIVE = 1
    TRANSMIT = 2
    CAT_CONTROL = 4

class Interface(BaseModel):
    name: str
    description: str
    type: InterfaceType
    capabilities: InterfaceCapability
    address: str
    priority: int = 0