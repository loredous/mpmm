from enum import Enum, Flag


class InterfaceType(Enum):
    KISS_TNC = 0
    TELNET = 1


class InterfaceCapability(Flag):
    RECEIVE = 1
    TRANSMIT = 2
    CAT_CONTROL = 4


class RemoteType(Enum):
    BBS = 1


class MessageType(Enum):
    PACKET_MESSAGE = 1
    PACKET_BULLETIN = 2
    PACKET_TRAFFIC = 3
    WINLINK = 4
    APRS = 5


class MessageDirection(Enum):
    INCOMING = 1
    OUTGOINT = 2
