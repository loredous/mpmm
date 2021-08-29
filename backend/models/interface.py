from pydantic import BaseModel
from models.enums import InterfaceCapability, InterfaceType


class Interface(BaseModel):
    name: str
    description: str
    type: InterfaceType
    capabilities: InterfaceCapability
    address: str
    priority: int = 0
