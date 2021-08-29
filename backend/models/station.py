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

    def get_base_config(self):
        return {
            "callsign": self.callsign,
            "location": self.location,
            "locator": self.locator,
            "interfaces": len(self.interfaces),
            "operators": len(self.operators),
            "remotes": len(self.remotes),
            "messages": len(self.messages)
        }
