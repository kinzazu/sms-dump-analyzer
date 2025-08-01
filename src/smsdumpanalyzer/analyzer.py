from smsdumpanalyzer.msgstore import MessageStore, Message
from smsdumpanalyzer.models import MsgType


class MessageChain(object):
    def __init__(self, msgstore: MessageStore, msisdn: str):
        self._chain = []
        self._msg_store = msgstore
        self._desired_msisdn = msisdn
        self.__messages_by_msisdn = []

    # Buisness logic for msisdn
    def build(self):
        # found all messages with desired msisdn
        messages_by_msisdn = self._get_messages_by_msisdn()
        # found all resps for this messages
        sri_resp, mo_resp_list = self._get_messages_by_tid(messages_by_msisdn)
        # third stage
        fsm = self._get_mt_by_imsi(sri_resp)
        fsm_resp = self._get_forward_sm_resp(fsm)

        self.fill_chain(messages_by_msisdn,sri_resp,mo_resp_list,fsm_resp)

    def fill_chain(self, *args):
        for list_ in args:
            self._chain.extend(list_)


    def get_chain(self):
        return sorted(self._chain, key=lambda msg: msg.time)

    """ 
    1. Search all messages with msisdn info. Possible variants (SRI or Mo-ForwardSM)
    2. 
    """
    def _get_messages_by_msisdn(self) -> list:
        return self._msg_store.by_msisdn(self._desired_msisdn)

    def _get_messages_by_tid(self, messages: list[Message]) -> tuple:
        sri_resp= set()
        mo_resp= set()

        for msg in messages:
            if  msg.opcode == MsgType.SRI:
                result = [resp for resp in self._msg_store.by_tid(msg.tid) if resp.opcode == MsgType.ResultLast or resp.opcode == MsgType.Error]
                sri_resp.update(result)
            if  msg.opcode == MsgType.MO_Forward_SM:
                result = [resp for resp in self._msg_store.by_tid(msg.tid) if resp.opcode == MsgType.ResultLast or resp.opcode == MsgType.Error]
                mo_resp.update(result)

        return self.sort_by_datetime(sri_resp), self.sort_by_datetime(mo_resp)

    def _get_mt_by_imsi(self, messages: list[Message]) -> list|tuple:
        fsm = set()

        for msg in messages:
            result = [msg for msg in self._msg_store.by_imsi(msg.imsi) if msg.opcode == MsgType.Forward_SM or msg.opcode == MsgType.MT_Forward_SM]
            fsm.update(result)
        return self.sort_by_datetime(fsm)

    def _get_forward_sm_resp(self, messages: list[Message]) -> list|tuple:
        fsm_resp = set()
        for msg in messages:
            result = [resp for resp in self._msg_store.by_tid(msg.tid) if resp.opcode == MsgType.ResultLast]
            fsm_resp.update(result)

        return self.sort_by_datetime(fsm_resp)



    @staticmethod
    def sort_by_datetime( _list: list[Message]|set[Message]) -> list|tuple:
        return sorted(_list, key=lambda msg: msg.time)



