import os
from functools import total_ordering
from typing import Iterable, List
from datetime import datetime
from .models import Message, MsgType


class Reporter:
    @classmethod
    def _direction(cls, opcode: MsgType | None) -> str:
        """

        """
        out = [MsgType.SRI, MsgType.MO_Forward_SM]
        return "out" if opcode in out else "in"

    @classmethod
    def _fmt_time(cls, ts: datetime) -> str:
        return ts.strftime("%d/%m %H:%M:%S")


class AsciiReporter(Reporter):
    """
    Class responsible for generating ASCII-formatted reports of message chains.

    This class is used to process and display structured information about
    messages within a chain in a readable ASCII-based format. It provides
    methods to render chain data for terminal-friendly output.

    :ivar total_width: Total width of the ASCII-rendered output in characters.
    :type total_width: Int
    """

    def __init__(self, total_width: int = 80) -> None:
        # ─ + (│) + стрелки => 54 выглядит читаемо в терминале 80 col
        self.total_width = max(total_width, 40)


    # ────────────────────────────────────────────────────────── public ──
    def render(self, chain: Iterable[Message]) -> str:
        msgs: List[Message] = list(chain)
        if not msgs:
            return "<empty chain>"

        # Get Header from the 1st message
        msisdn = msgs[0].msisdn or "<unknown-msisdn>"
        opc = msgs[0].opc if msgs[0].opc is not None else "--"
        dpc = msgs[0].dpc if msgs[0].dpc is not None else "--"
        opc_len = len(f"OPC: {opc}")
        dpc_len = len(f"DPC: {dpc}")

        left_border = "│"
        right_border = "│"

        header = f"Subscriber: {msisdn} "
        header = left_border + f"{header:─^{self.total_width -2}}" + right_border

        # lines = [
        #     header,
        #     f"{left_border} OPC: {opc:<{self.total_width/2 - opc_len}}"
        #     f" DPC: {dpc:>{self.total_width / 2 - dpc_len}} {right_border}",
        #     f"{left_border}{' ' * (self.total_width - 2)}{right_border}",
        # ]
        # TODO: В итоге почему-то в данном месте длинна строки self.total_width - opc_len \
        # TODO: Высчитавается на 2 символа меньше чем ожидается без явной на то причины. Надо разобраться почему
        lines = [
            header,
            f"│ OPC: {opc:<{self.total_width - dpc_len - opc_len}} DPC: {dpc:} │",
            f"{left_border}{' ' * (self.total_width - 2)}{right_border}",
        ]

        known_pc = [opc,dpc]
        for msg in msgs:
            if msg.opc not in known_pc or msg.dpc not in known_pc:
                lines.append(f"│ OPC: {msg.opc:<{self.total_width - dpc_len - opc_len }} DPC: {msg.dpc:} │")

            time_line = (
                f"{left_border} {self._fmt_time(msg.time):<{self.total_width - 4}} "
                f"{right_border}"
            )
            lines.append(time_line)

            # строка-сообщение
            direction = self._direction(msg.opcode)
            opcode_name = (msg.opcode.name if msg.opcode else "Unknown").ljust(15)
            tid = (msg.tid or "--").ljust(14)


            if direction == "out":
                #  | ├── <name> TID=... ─────▶  |
                match msg.opcode:
                    case MsgType.SRI | MsgType.MO_Forward_SM:
                        msg_info = f" TID={tid} {opcode_name}  MSISDN={msg.msisdn} "
                    case MsgType.Forward_SM | MsgType.MT_Forward_SM:
                        msg_info = f" TID={tid} {opcode_name} IMSI={msg.imsi} "
                    case _:
                        msg_info = f" TID={tid} {opcode_name} "

                body = f"├─{msg_info:─^{self.total_width - 4}}▶{right_border}"

            else:
                #  | ◀──── <name> TID=... ──┤ |
                msg_info = f" TID={tid} {opcode_name} IMSI={msg.imsi} "
                body = (
                    f"{left_border}◀{msg_info:─^{self.total_width - 4}}─┤"
                )



            lines.append(body)

        # финальная пустая строка-разделитель
        lines.append(f"{left_border}{' ' * (self.total_width - 2)}{right_border}")

        return "\n".join(lines)


class MarkdownReporter(Reporter):
    HEADER = "# Report"


    def _ensure_report_dir(self):
        os.makedirs("./reports", exist_ok=True)


    def get_participants(self, chain) -> list[str]:
        # not using set cuz it's not ordered
        participants = []
        for msg in chain:
            if msg.opcode not in participants:
                participants.append(msg.opc)
            if msg.dpc not in participants:
                participants.append(msg.dpc)
        return [*participants]


    def render(self, chain: list[Message]) -> str:
        msgs: List[Message] = list(chain)
        if not msgs:
            return "<empty chain>"

        # Get Header from the 1st message
        msisdn = msgs[0].msisdn or "<unknown-msisdn>"
        opc = msgs[0].opc if msgs[0].opc is not None else "--"
        dpc = msgs[0].dpc if msgs[0].dpc is not None else "--"
        opc_len = len(f"OPC: {opc}")
        dpc_len = len(f"DPC: {dpc}")

        lines = [self.HEADER,
                 f"**Subscriber**: {msisdn}",
                 "",
                 f"total messages: {len(msgs)}",
                 ""]


        lines.extend(["```mermaid",
                      "sequenceDiagram"])

        lines.extend([f"participant _{x} as {x}" for x in self.get_participants(chain)])

        for msg in msgs:
            direction = self._direction(msg.opcode)

            # if direction == "out":
            # lines.append(f"_{msg.opc} ->> _{msg.dpc}: {self._fmt_time(msg.time)} {msg.opcode.name} tid = {msg.tid}")

            match msg.opcode:
                case MsgType.SRI | MsgType.MO_Forward_SM:
                    lines.append(f"_{msg.opc} ->>+ _{msg.dpc}: ")
                    lines[-1] += f"{self._fmt_time(msg.time)}<br>tid = {msg.tid}<br>{msg.opcode.name}<br>MSISDN = {msg.msisdn}"
                case MsgType.MT_Forward_SM | MsgType.ResultLast:
                    lines.append(f"_{msg.opc} ->>- _{msg.dpc}: ")
                    lines[-1] += f"{self._fmt_time(msg.time)}<br>tid = {msg.tid}<br>{msg.opcode.name}<br>IMSI = {msg.imsi}"
                case MsgType.Error:
                    lines.append(f"_{msg.opc} ->>- _{msg.dpc}:")
                    lines[-1] += f"{self._fmt_time(msg.time)}<br>tid = {msg.tid}<br>{msg.opcode.name}<br>ErrorCode = {msg.imsi}"
                case _:
                    lines.append(f"note over _{msg.opc}, _{msg.dpc}: {msg=}")


            # lines.append(f"_{msg.opc} ->> _{msg.dpc}: {msg.opcode} tid = {msg.tid}")



        lines.append("```")
        self._ensure_report_dir()
        with open(f'./reports/{msisdn}.md', 'w') as f:
            f.write("\n".join(lines))
        return "\n".join(lines)

#TODO PlantUML render
class PlantUMLReporter(Reporter):

    def render(self, chain: list[Message]) -> str:
        """

        :param chain:
        :return:
        """

        """
Header

```plantuml
@startuml
participant 14685 [
    =14685
]


participant 10521 [
    =10521
]

14685 -> 10521 ++ #green :25/03 08:26:23\n**TID = 00:49:00:44** //MO_Forward_SM//  MSISDN = 79620770446

10521 -> 14685 -- : 25/03 08:26:25\n**TID = 00:49:00:44** //ResultLast// IMSI = None

10521 -> 10287 ++: 25/03 08:26:25\n//SRI// tid = **2f:7a:c6:22** MSISDN = 79620770446
10287 -> 10521 --:25/03 08:26:26\nError tid = 2f:7a:c6:22 ErrorCode = UnknownSubscriber
10521 -> 10287 ++: 25/03 08:27:26\nSRI tid = 2f:94:5e:3e MSISDN = 79620770446
10288 -> 10521 :25/03 08:27:26\nError tid = 2f:94:5e:3e ErrorCode = UnknownSubscriber
10521 -> 10287 ++: 25/03 08:29:26\nSRI tid = 2f:ae:06:63 MSISDN = 79620770446
10287 -> 10521 --:25/03 08:29:26\nError tid = 2f:ae:06:63 ErrorCode = UnknownSubscriber
@enduml
```"""