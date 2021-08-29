from typing import Optional
from pydantic import BaseModel


class Operator(BaseModel):
    callsign: str
    name: Optional[str]
