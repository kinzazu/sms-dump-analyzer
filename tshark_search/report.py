from .models import Transaction

class AsciiReporter:
    def render(self, tx: Transaction) -> str:
        lines = []
        for m in sorted(tx.messages, key=lambda x: x.time):
            lines.append(f"{m.time:.3f}  {m.kind.name:8}  TID={m.tid}  IMSI={m.imsi}")
        return "\n".join(lines)

