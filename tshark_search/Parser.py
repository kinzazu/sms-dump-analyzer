import json
from typing import Iterable, Dict, Any, Literal
from unittest import case

from tshark_search.models import TCAPState, ErrorCode
from .models import Message, MsgType, TCAPState, RPDestinationAddress, MessageTypeIndicator
from enum import Enum
from datetime import datetime, timezone


# ─── MAP specific JSON keys ─────────────────────────────────────────────────────
class JsonField(str, Enum):
    """Immutable constants for tshark JSON fields."""
    COMPONENT_TREE_KEY     = "gsm_map.old.Component_tree"
    INVOKE_ELEMENT_KEY     = "gsm_old.invoke_element"
    RETURN_RESULT_LAST_KEY = "gsm_old.returnResultLast_element"
    OPCODE_LOCAL_VALUE_KEY = "gsm_old.opCode_tree"
    LOCAL_VALUE_FIELD      = "gsm_old.localValue"
    MSISDN_KEY             = "gsm_map.sm.msisdn_tree"
    IMSI_KEY               = "e212.imsi"
    EnumErrorCause         = "gsm_map.er.sm_EnumeratedDeliveryFailureCause"
    ErrorCode              = "gsm_map.er.sm_ErrorCode"
    Error                  = "errorCode_tree"
    OldErrorTree           = "gsm_old.returnError_element"


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

    def _frame_to_msg(self, frame: dict) -> Message:
        layers = frame["_source"]["layers"]
        # generate timestamp
        ts = float(layers["frame"]["frame.time_epoch"])
        ts = datetime.fromtimestamp(ts).astimezone(timezone.utc)

        # helpers
        m3ua_json = layers['m3ua']
        tcap_json = layers['tcap']
        gsm_map = layers['gsm_map']['gsm_map.old.Component_tree']

        # specific for sms
        sms_pdu = layers.get('gsm_sms')

        #fill tcap
        tid, tcap_state = self._fill_tcap(tcap_json)

        # Initialize message
        message = Message(time=ts,
                          tid=tid,
                          tcap_state=tcap_state)

        #fill_map_part
        message = self._new_fill_gsm_map(gsm_map,message)
        # message = self._fill_gsm_map(gsm_map, message)

        # fill sms part
        if sms_pdu is not None:
            message = self._fill_sms_fields(sms_pdu, message)

        # fill m3ua
        message.opc, message.dpc = self._fill_m3ua_pc(m3ua_json=m3ua_json)
        return message

    @staticmethod
    def _fill_tcap(tcap_json: dict) -> tuple[Any, Literal[TCAPState.Begin, TCAPState.End, TCAPState.Continue]]:
        if tcap_json.get('tcap.begin_element') is not None:
            tid = tcap_json['tcap.begin_element']['tcap.tid']
            tcap_state = TCAPState.Begin
        elif tcap_json.get('tcap.end_element') is not None:
            tid = tcap_json['tcap.end_element']['tcap.tid']
            tcap_state = TCAPState.End
        elif tcap_json.get('tcap.continue_element') is not None:
            tid = tcap_json['tcap.continue_element']['tcap.tid']
            tcap_state = TCAPState.Continue
        else:
            raise RuntimeError(f"Cound't parse TCAP info. tcap_json is empty: {tcap_json}")

        return tid, tcap_state

    # @staticmethod
    def _rd_da_based_fill(self, gsm_invoke: dict, msg):
        rd_da = "gsm_map.sm.sm_RP_DA"
        old_rd_da = "gsm_old.sm_RP_DA"


        if rd_da in gsm_invoke.keys():
            rp_da_val = int(gsm_invoke.get("gsm_map.sm.sm_RP_DA"))
            sm_rp_da_tree = gsm_invoke.get('gsm_map.sm.sm_RP_DA_tree')
        elif old_rd_da in gsm_invoke.keys():
            rp_da_val = int(gsm_invoke.get("gsm_old.sm_RP_DA"))
            sm_rp_da_tree = gsm_invoke.get('gsm_old.sm_RP_DA_tree')
        else:
            print('[ERROR] no rd_da')
            sm_rp_da_tree = {}

        match RPDestinationAddress(rp_da_val):
            case RPDestinationAddress.IMSI:
                msg.imsi = sm_rp_da_tree.get('e212.imsi')

            case RPDestinationAddress.LMSI:
                # TODO processing of the LMSI
                print('я хз что с этим делать пока')

            case RPDestinationAddress.MSISDN:
                print(f'{msg.tid}. Unsupported type RP-DA value: {rp_da_val}')

            case RPDestinationAddress.ServiceCenterAddress:
                pass
                # print(f'{msg.tid}. Unsupported type RP-DA value: {rp_da_val}')
            case _:
                print(rp_da_val, msg.tid)
                raise RuntimeError('unknown rp_da_val')

        return msg

    # @staticmethod

    def _(self): pass

    def _new_fill_gsm_map(self, gsm_layer_json: dict,msg: Message):
        """
        New parsing logic based on tcap transaction type and possible context-names
        """
        match msg.tcap_state:
            case TCAPState.Begin | TCAPState.Continue :
                gsm_invoke = gsm_layer_json.get('gsm_old.invoke_element')
                if gsm_invoke is None:
                    #TODO processing options for a empty invoke
                    raise RuntimeError(f'gsm_invoke, {gsm_layer_json}')

                msg.opcode = self._gms_opcode_from_invoke(gsm_invoke)

                match msg.opcode:
                    case MsgType.SRI:
                        msg.msisdn = gsm_invoke['gsm_map.sm.msisdn_tree']['e164.msisdn']
                    case MsgType.Forward_SM:
                        msg = self._rd_da_based_fill(gsm_invoke, msg)


            case TCAPState.End:
                result_tree = gsm_layer_json.keys()
                if JsonField.RETURN_RESULT_LAST_KEY in result_tree:
                    result_element = gsm_layer_json.get(JsonField.RETURN_RESULT_LAST_KEY)
                    # Get result element tree
                    r_e_tree = result_element.get('gsm_old.resultretres_element')

                    if r_e_tree is None:
                        keys_analis = [x for x in result_element.keys()]
                        keys_analis.remove('gsm_old.invokeID')
                        if keys_analis:
                            for key in keys_analis:
                                result_element = gsm_layer_json.get(key)
                                print(result_element)

                        # possibly just a good empty response
                        msg.opcode = MsgType.ResultLast
                        return msg
                    # while r_e_tree is None:
                    #     if r_e_tree is None:
                    #         r_e_tree = result_element.get('gsm_map.sm.sm_RP_DA_tree')

                    msg.imsi = r_e_tree.get('e212.imsi')
                    opcode = int(r_e_tree.get('gsm_old.opCode', -1))
                    if opcode != -1:
                        msg.opcode = MsgType(opcode)

                elif JsonField.Error in result_tree:
                    print('error ola la', gsm_layer_json.get(JsonField.Error))
                elif JsonField.OldErrorTree in result_tree:
                    msg.opcode = MsgType.Error
                    # TODO replace for proper Error class.
                    err_code_tree = gsm_layer_json[JsonField.OldErrorTree].get('gsm_old.errorCode_tree')
                    err_code = err_code_tree.get('gsm_old.localValue', '-1')
                    msg.imsi = f"{ErrorCode(int(err_code)).name}"
                else:
                    msg.opcode = MsgType.ResultLast

        return msg

    def _gms_opcode_from_invoke(self, invoke_json):
        val = invoke_json.get('gsm_old.opCode_tree')
        if val is None:
            # TODO processing for a empty opcode tree
            raise RuntimeError(f'gsm_invoke, {invoke_json}')

        opcode = int(val.get('gsm_old.localValue', -1))

        return MsgType(opcode)

    def _fix_tp_da_key(self, map_gms_json):
        """
        Normalize the TP-Destination-Address key emitted by tshark.

        Tshark sometimes names the field `TP-Destination-Address…`.  We want it
        to be called `tp-destination-address` for downstream processing.
        """
        names = ['TP-Originating-Address', 'TP-Destination-Address', 'TP-Recipient-Address']
        for name in names:
            destination_address_keys = [key for key in map_gms_json.keys() if key.startswith(name)]
            if destination_address_keys:
                original_key = destination_address_keys[0]
                map_gms_json[name.lower()] = map_gms_json.pop(original_key)
        return map_gms_json

    def _fill_sms_fields(self, sms_json, msg: Message) -> Message:
        sms_json = self._fix_tp_da_key(sms_json)
        mti = int(sms_json["gsm_sms.tp-mti"])
        mti = MessageTypeIndicator(mti)

        # TODO: error with message tid == 60:00:03:05, 'packets-2025-05-16'
        match mti:
            case MessageTypeIndicator.MT:
                # print(sms_json.get("tp-destination-address"))
                # msg.imsi = sms_json.get("tp-destination-address")
                pass
            case MessageTypeIndicator.MO:
                try:
                    msg.msisdn = sms_json["tp-destination-address"]['gsm_sms.tp-da']
                except KeyError:
                    print(f'Failed to parse gsm_sms. {msg.tid= }, {sms_json=}')
            # case _:
            #     raise RuntimeError(f"Couldn't parse {sms_json}")
        return msg

    def _fix_m3ua_keys(self, m3ua_json):
        broken_keys = [key for key in m3ua_json.keys() if key.startswith("Protocol data")]
        if broken_keys:
            original_key = broken_keys[0]
            m3ua_json["protocol-data"] = m3ua_json.pop(original_key)
        return m3ua_json

    def _fill_m3ua_pc(self, m3ua_json):

        m3ua_json = self._fix_m3ua_keys(m3ua_json)

        opc =  m3ua_json["protocol-data"].get("m3ua.protocol_data_opc")
        dpc = m3ua_json["protocol-data"].get("m3ua.protocol_data_dpc")

        return opc, dpc
