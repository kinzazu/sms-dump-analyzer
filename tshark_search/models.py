from dataclasses import dataclass
from enum import Enum
from typing import Optional
from datetime import datetime


class FilterField(str, Enum):  # NEW
    """Immutable constants for tshark display-filter fields."""
    MSISDN   = 'e164.msisdn'
    TCAP_TID = 'tcap.tid'
    IMSI     = 'e212.imsi'


#SM-RP-DA
# noinspection SpellCheckingInspection
class RPDestinationAddress(Enum):
    """ShortMessage Relay Protocol Destination Address type"""
    IMSI                 = 0
    LMSI                 = 1
    MSISDN               = 2
    roaming_number       = 3
    ServiceCenterAddress = 4


# SMS Transfer Protocol Message Type Indicator (TP-MTI)
class MessageTypeIndicator(Enum):
    SMS_DELIVER = 0  # Mobile Terminated
    SMS_SUBMIT  = 1  # Mobile Originated
    MT          = 0
    MO          = 1


# OpCode
class MsgType(Enum):
    Unknown    = -1
    ResultLast = 0
    MT_Forward_SM = 44


    SRI        = 45
    MO_Forward_SM = 46
    # MAP version != 3
    Forward_SM = 46
    Report_SM_DeliveryStatus        = 47
    AlertServiceCentreWithoutResult = 49
    readyForSM                      = 66


class TCAPState(Enum):
    Begin    = 0
    Continue = 1
    End      = 2

@dataclass
class Message:
    time:       datetime
    opcode:     Optional[MsgType] = MsgType.Unknown
    tcap_state: Optional[TCAPState] = None
    tid:        Optional[str] = None
    msisdn:     Optional[str] = None
    imsi:       Optional[str] = None


@dataclass
class Transaction:
    tid: str
    opcodes: set[MsgType]
    msisdn: str | None
    imsi: str | None
    msgs : list[Message] | None

    def add(self, msg: Message):
        self.msgs.append(msg)
        self.opcodes.add(msg.opcode)

