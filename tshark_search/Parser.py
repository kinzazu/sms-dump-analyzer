import json
from typing import Iterable, Dict
from unittest import case

from .models import Message, MsgType, TCAPState, RPDestinationAddress, MessageTypeIndicator
from enum import Enum
from datetime import datetime, timezone

# ─── MAP specific JSON keys ─────────────────────────────────────────────────────
class JsonField(str, Enum):
    """Immutable constants for tshark JSON fields."""
    COMPONENT_TREE_KEY       = "gsm_map.old.Component_tree"
    INVOKE_ELEMENT_KEY       = "gsm_old.invoke_element"
    RETURN_RESULT_LAST_KEY   = "gsm_old.returnResultLast_element"
    OPCODE_LOCAL_VALUE_KEY   = "gsm_old.opCode_tree"
    LOCAL_VALUE_FIELD        = "gsm_old.localValue"
    MSISDN_KEY               = "gsm_map.sm.msisdn_tree"
    IMSI_KEY                 = "e212.imsi"



class JsonParser:
    """
    A class that provides functionality to parse frames and construct messages.

    This class processes JSON data, typically from network protocols such as TCAP
    (Transaction Capabilities Application Part) and GSM MAP (Global System for Mobile
    Communications Mobile Application Part), to generate structured `Message` objects.

    Attributes and helper methods in this class are used to parse different layers of
    protocol data and fill the respective fields in the resulting `Message` object.

    :ivar attribute1: Placeholder description of attribute1.
    :ivar attribute2: Placeholder description of attribute2.
    """

    # ---------- api --------------
    def parse_frame(self, frame) -> Message:
        return self._frame_to_msg(frame)

    def parse_frames(self, frames: list[dict]) -> Iterable[Message]:
        for f in frames:
            yield self._frame_to_msg(f)

    # ---------- helpers ----------
    def _frame_to_msg(self, frame: dict) -> Message:
        layers    = frame["_source"]["layers"]
        ts        =  float(layers["frame"]["frame.time_epoch"])
        ts        = datetime.fromtimestamp(ts).astimezone(timezone.utc)
        tcap_json = layers['tcap']
        gsm_map   = layers['gsm_map']['gsm_map.old.Component_tree']
        sms_pdu = layers.get('gsm_sms')
        message   = Message(time = ts)

        #fill tcap
        message = self._fill_tcap(tcap_json, message)
        #fill_map_part
        message = self._fill_gsm_map(gsm_map, message)
        # fill sms part
        if sms_pdu is not None:
            message = self._fill_sms_fields(sms_pdu, message)

        return message

    @staticmethod
    def _fill_tcap(tcap_json: dict, msg) -> Message:
        if tcap_json.get('tcap.begin_element') is not None:
            msg.tid = tcap_json['tcap.begin_element']['tcap.tid']
            msg.tcap_state = TCAPState.Begin
        elif tcap_json.get('tcap.end_element') is not None:
            msg.tid = tcap_json['tcap.end_element']['tcap.tid']
            msg.tcap_state = TCAPState.End
        elif tcap_json.get('tcap.continue_element') is not None:
            msg.tid = tcap_json['tcap.continue_element']['tcap.tid']
            msg.tcap_state = TCAPState.Continue
        else:
            raise RuntimeError(f"Cound't parse TCAP info. tcap_json is empty: {tcap_json}")

        return msg

    # @staticmethod
    def _rd_da_based_fill(self, rp_da_val, gsm_invoke, msg):
        rp_da_val = int(rp_da_val)
        rp_da_val = RPDestinationAddress(rp_da_val)
        match rp_da_val:
            case RPDestinationAddress.IMSI:
                sm_rp_da_tree = gsm_invoke.get('gsm_map.sm.sm_RP_DA_tree')

                if sm_rp_da_tree is  None:
                    sm_rp_da_tree = gsm_invoke.get('gsm_old.sm_RP_DA_tree')

                msg.imsi = sm_rp_da_tree.get('e212.imsi')

            case RPDestinationAddress.LMSI:
                # TODO доделать обработку LMSI
                print('я хз что с этим делать пока')

            case RPDestinationAddress.MSISDN:
                print(f'{msg.tid}. Unsupported type RP-DA value: {rp_da_val}')
            case RPDestinationAddress.ServiceCenterAddress:
                pass
                # print(f'{msg.tid}. Unsupported type RP-DA value: {rp_da_val}')
            case _:
                raise RuntimeError('unknown rp_da_val')

        return msg


    # @staticmethod
    def _fill_gsm_map(self, json_dict: dict, msg: Message) -> Message:
        # msg.opcode = MsgType.Unknown
        gsm_invoke = json_dict.get('gsm_old.invoke_element')
        result_last = json_dict.get('gsm_old.returnResultLast_element')
        if gsm_invoke is not None:
            val = gsm_invoke['gsm_old.opCode_tree']['gsm_old.localValue']
            try:
                msg.opcode = MsgType(int(val))
            except (ValueError,KeyError) as e:
                print(f"Couldn't convert {val} type {type(val)} to int. full traceback: {e}")

        if result_last is not None:
            msg.opcode = MsgType.ResultLast

        match msg.opcode:
            case MsgType.SRI:
                if msg.tcap_state == TCAPState.Begin:
                    msg.msisdn = gsm_invoke['gsm_map.sm.msisdn_tree']['e164.msisdn']
                if msg.tcap_state == TCAPState.End:
                    msg.imsi = gsm_invoke['e212.imsi']
            case MsgType.Forward_SM:
                rp_da_type = gsm_invoke.get("gsm_map.sm.sm_RP_DA")
                old_rp_da = gsm_invoke.get('gsm_old.sm_RP_DA')
                if rp_da_type is not None:
                    # TODO решить что делать при проверке rp-da
                    msg = self._rd_da_based_fill(rp_da_type, gsm_invoke, msg)
                elif old_rp_da is not None:
                    msg = self._rd_da_based_fill(old_rp_da, gsm_invoke, msg)
                else:
                    print(f"SM-RP-DA for {rp_da_type=} not found. gms_json: {gsm_invoke=}")
                    raise AttributeError(f"SM-RP-DA for", rp_da_type)

            case MsgType.ResultLast:
                pass

            # case _:
            #     raise RuntimeError(f'unknown opcode: {msg.opcode}')

        return msg


    def _fix_tp_da_key(self, map_gms_json):
        """
        Normalise the TP-Destination-Address key emitted by tshark.

        Tshark sometimes names the field `TP-Destination-Address…`.  We want it
        to be called `tp-destination-address` for downstream processing.
        """
        destination_address_keys = [key for key in map_gms_json.keys() if key.startswith("TP-Destination-Address")]
        if destination_address_keys:
            original_key = destination_address_keys[0]
            map_gms_json["tp-destination-address"] = map_gms_json.pop(original_key)

        originating_address_keys = [key for key in map_gms_json.keys() if key.startswith("TP-Originating-Address")]
        if originating_address_keys:
            original_key = originating_address_keys[0]
            map_gms_json["tp-originating-address"] = map_gms_json.pop(original_key)

        return map_gms_json


    def _fill_sms_fields(self, sms_json, msg: Message) -> Message:
        sms_json = self._fix_tp_da_key(sms_json)
        mti = int(sms_json["gsm_sms.tp-mti"])
        mti = MessageTypeIndicator(mti)

        match mti:
            case MessageTypeIndicator.MT:
                # print(sms_json.get("tp-destination-address"))
                # msg.imsi = sms_json.get("tp-destination-address")
                pass
            case MessageTypeIndicator.MO:
                msg.msisdn = sms_json["tp-destination-address"]['gsm_sms.tp-da']
            # case _:
            #     raise RuntimeError(f"Couldn't parse {sms_json}")

        return msg











