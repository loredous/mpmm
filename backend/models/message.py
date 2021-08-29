from models.remote import Remote
from typing import List, Optional
from pydantic import BaseModel, Field
from models.enums import MessageType, MessageDirection
from datetime import datetime


class Message(BaseModel):
    remote_identifier: Optional[str]
    msg_to: List[str] = []
    msg_from: str
    created: datetime = Field(default_factory=datetime.utcnow)
    last_operation_time: Optional[datetime]
    via: List[Remote]
    direction: MessageDirection
    type: MessageType
    subject: Optional[str]
    text: str
    draft: bool = False
    pending_transmission: bool = False
