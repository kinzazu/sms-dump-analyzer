from msgstore import MessageStore, Message


class MessageChain(object):
    def __init__(self, msgstore: MessageStore, msisdn: str):
        self._msg_store = msgstore
        self._desired_msisdn = msisdn
        self.messages = []
        self.__messages_by_msisdn = []

    # Buisness logic for msisdn
    def build(self):
        # found all messages with desired msisdn
        first_stage = self._msg_store.get_messages_by_msisdn()
        # found all resps for this messages
        second_stage = self._msg_store.get_messages_by_tid(first_stage)
        # third stage



    """ 
    1. Search all messages with msisdn info. Possible variants (SRI or Mo-ForwardSM)
    2. 
    """
    def _get_messages_by_msisdn(self) -> list:
        return self._msg_store.by_msisdn(self._desired_msisdn)

    def _get_messages_by_tid(self, messages: list[Message]) -> list:
        tid_messages = set()

        for msg in messages:
            tid_messages.update(self._msg_store.by_tid(msg.tid))

        return self.sort_by_datetime(tid_messages)


    @staticmethod
    def sort_by_datetime( _list: list[Message]|set[Message]) -> list|tuple:
        return sorted(_list, key=lambda msg: msg.datetime)



