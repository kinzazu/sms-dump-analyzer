from typing import List, Iterable
from pathlib import Path
from smsdumpanalyzer.capinfo import CapInfo


class FilePool:
    def __init__(self, dump_folder: str):
        self.__dump_folder = self._process_to_path(dump_folder)
        self._files: set[CapInfo] = set()
        self._scan(self.__dump_folder)

    def __repr__(self):
        return f"{self.__dump_folder} : {len(self._files)}"

    def add_file(self, file_path: Path):
        meta = CapInfo.form_info(file_path)
        # print(meta)
        self._files.add(meta)

    # ---------- public API ----------
    def select(self, since, to) -> Iterable[CapInfo]:
        for meta in self._files:
            if not (meta.ts_end < since or meta.ts_start > to):
                yield meta

    def _process_to_path(self, folder: str) -> Path:
        _folder = Path(folder)
        try:
            _folder =  _folder.expanduser()
        except RuntimeError:
            print('no home folder provided')
        return _folder

    # ---------- helpers ----------
    def _scan(self, folder: Path):

            for p in folder.glob("*.pcapng"):
                self.add_file(p)
            for p in folder.glob("*.pcap"):
                self.add_file(p)

