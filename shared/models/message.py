from shared.models.remote import Remote
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime

class MessageType(Enum):
    PACKET_MESSAGE = 1
    PACKET_BULLETIN = 2
    PACKET_TRAFFIC = 3
    WINLINK = 4
    APRS = 5

class MessageDirection(Enum):
    INCOMING = 1
    OUTGOINT = 2

class Message(BaseModel):
    remote_identifier: Optional[str]
    msg_to: List[str]
    msg_from: str
    created: datetime = Field(default_factory=datetime.utcnow)
    last_operation_time: Optional[datetime]
    via: List[Remote]
    subject: Optional[str]
    text: str
    draft: bool = False
    pending_transmission: bool = False