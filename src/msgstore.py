from collections import defaultdict
from dataclasses import dataclass
from .models import Message, MsgType
from typing import Iterator

@dataclass()
class _Bucket:
    """Примитивный контейнер атрибут → список индексов."""
    by_tid: dict[str, list[int]]
    by_msisdn: dict[str, list[int]]
    by_opcode: dict[int, list[int]]


class MessageStore:
    def __init__(self):
        self._all: list[Message] = []
        self._by_tid    = defaultdict(list)
        self._by_msisdn = defaultdict(list)
        self._by_opcode = defaultdict(list)
        self._by_imsi   = defaultdict(list)

    def add(self, msg: Message):
        idx = len(self._all)
        self._all.append(msg)
        if msg.tid:               self._by_tid[msg.tid].append(idx)
        if msg.msisdn:            self._by_msisdn[msg.msisdn].append(idx)
        if msg.imsi:              self._by_imsi[msg.imsi].append(idx)
        self._by_opcode[msg.opcode].append(idx)

   # ---------- запросы ----------
    def by_tid(self, tid: str) -> list[Message]:
       return [self._all[i] for i in self._by_tid.get(tid, [])]

    def by_msisdn(self, num: str) -> list[Message]:
       return [self._all[i] for i in self._by_msisdn.get(num, [])]

    def by_imsi(self, imsi: str) -> list[Message]:
        return [self._all[i] for i in self._by_imsi.get(imsi, [])]

    def by_opcode(self, opcode: MsgType) -> list[Message]:
       return [self._all[i] for i in self._by_opcode.get(opcode, [])]

    def filter_all(self) -> Iterator[Message]:
       yield from self._all

    def sort_by_datetime(self):
        return sorted(self._all, key=lambda msg: msg.datetime)
