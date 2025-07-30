from dataclasses import dataclass
from enum import Enum
from typing import Optional
from datetime import datetime
from src.capinfo import CapInfo


class FilterField(str, Enum):  # NEW
    """Immutable constants for tshark display-filter fields."""
    MSISDN = 'e164.msisdn'
    TCAP_TID = 'tcap.tid'
    IMSI = 'e212.imsi'


#SM-RP-DA
# noinspection SpellCheckingInspection
class RPDestinationAddress(Enum):
    """ShortMessage Relay Protocol Destination Address type"""
    IMSI = 0
    LMSI = 1
    MSISDN = 2
    roaming_number = 3
    ServiceCenterAddress = 4


# SMS Transfer Protocol Message Type Indicator (TP-MTI)
class MessageTypeIndicator(Enum):
    SMS_DELIVER = 0  # Mobile Terminated
    SMS_SUBMIT = 1  # Mobile Originated
    MT = 0
    MO = 1
    SMS_STATUS_REPORT = 2


class OpCode(Enum):
    """
    Operation Code type. Contains only opcodes for the short message service
    """
    MT_Forward_SM                   = 44
    SRI                             = 45
    MO_Forward_SM                   = 46
    Report_SM_DeliveryStatus        = 47
    AlertServiceCentreWithoutResult = 49
    readyForSM                      = 66
    # if MAP version != 3
    Forward_SM                      = 46


# OpCodeesque class
class MsgType(Enum):
    Unknown = -1
    ResultLast = 0
    Error = 1
    MT_Forward_SM = 44
    SRI = 45
    MO_Forward_SM = 46
    # MAP version != 3
    Forward_SM = 46
    Report_SM_DeliveryStatus = 47
    AlertServiceCentreWithoutResult = 49
    readyForSM = 66


class TCAPState(Enum):
    Begin = 0
    Continue = 1
    End = 2

@dataclass
class TCAPContext:
    """
    can be filled with class data. Based on type we can check types of files
    """
    pass

class ErrorCode(Enum):
    Unknown = -1
    # Generic errors
    Systemfailure = 34
    DataMissing = 35
    UnexpectedDataValue = 36
    FacilityNotSupported = 21
    IncompatibleTerminal = 28
    ResourceLimitation = 51

    # Identificationand Numbering Errors
    UnknownSubscriber = 1
    NumberChanged = 144
    UnknownMSC = 3
    UnidentifiedSubscriber = 5
    UnknownEquipment = 7

    # Subscription Errors
    RoamingNotAllowed = 8
    IllegalSubscriber = 9
    IllegalEquipment = 12
    BearerServiceNotProvisioned = 10
    TeleserviceNotProvisioned = 11

    # Handover Errors
    NoHandoverNumberAvailable = 25
    SubsequentHandoverFailure = 26
    TargetCellOutsideGroupCallArea = 42

    # Operation and Maintenance Errors
    tracingBufferFull = 40

    # Call Handling Errors
    NoRoamingNumberAvailable = 39
    AbsentSubscriber = 27
    BusySubscriber = 45
    NoSubscriberReply = 46
    CallBarred = 13
    ForwardingViolation = 14
    ForwardingFailed = 47
    CUGReject = 15
    ORNotAllowed = 48

    # Any Time Interrogation Errors
    ATINotAllowed = 49

    # Any Time Information Handling Errors
    ATSINotAllowed = 60
    ATMNotAllowed = 61
    InformationNotAvailable = 62

    # Supplementary Service Errors
    IllegalSSOperation = 16
    SSErrorStatus = 17
    SSNotAvailable = 18
    SSSubscriptionViolation = 19
    SSIncompatibility = 20
    UnknownAlphabet = 71
    USSDBusy = 72
    PWRegistrationFailure = 37
    NegativePWCheck = 38
    NumberofPWAttemptsViolation = 43
    ShortTermDenial = 29
    LongTermDenial = 30

    # Short Message Service Errors
    SubscriberBusyForMTSMS = 31
    SMDeliveryFailure = 32
    MessageWaitingListFull = 33
    AbsentSubscriberforSM = 6

    # Group Call errors
    NoGroupCallNumberAvailable = 50
    OngoingGroupCall = 22

    # Location Service Errors
    UnauthorizedRequestingNetwork = 52
    UnauthorizedLCSClient = 53
    PositionMethodFailure = 54
    UnknownorUnreachableLCSClient = 58
    MMEventNotSupported = 59

@dataclass
class PDU:
    time:       datetime
    meta:       CapInfo = None
    tcap_state: Optional[TCAPState] = None
    tid:        Optional[str] = None
    opcode:     Optional[MsgType|OpCode] = MsgType.Unknown
    opc:        Optional[int] = None
    dpc:        Optional[int] = None

    def __hash__(self):
        hash_val = self.time.strftime("%c")
        hash_val += self.tid if self.tid else ""
        return hash(self.tid)


@dataclass(unsafe_hash=True)
class Message(PDU):
    # time: datetime
    # opcode:     Optional[MsgType] = MsgType.Unknown
    # tcap_state: Optional[TCAPState] = None
    # tid:        Optional[str] = None
    msisdn: Optional[str] = None
    imsi:   Optional[str] = None

    # def __hash__(self):
    #     return super().__hash__()


@dataclass
class Response(PDU):
    opcode: Optional[MsgType] = None
    imsi: Optional[str] = None


@dataclass
class Error(PDU):
    code: ErrorCode = None
    message: str = None
