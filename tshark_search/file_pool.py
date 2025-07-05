from typing import List, Iterable
from pathlib import Path
from .capinfo import CapInfo


class FilePool:
    def __init__(self, dump_folder: Path):
        self._files: set[CapInfo] = set()
        self._scan(dump_folder)

    def add_file(self, file_path: Path):
        meta = CapInfo(file_path)
        print(meta)
        self._files.add(meta)

    # ---------- public API ----------
    def select(self, since, to) -> Iterable[CapInfo]:
        for meta in self._files:
            if not (meta.ts_end < since or meta.ts_start > to):
                yield meta

    # ---------- helpers ----------
    def _scan(self, folder: Path):
        for p in Path(folder).glob("*.pcap*"):
            self.add_file(p)