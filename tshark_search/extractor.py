import datetime
# from enum import Enum
from pathlib import Path

from tshark_search.Parser import JsonParser
from tshark_search.models import FilterField
import json
import subprocess

# FIELDS = ["frame.number", "frame.time_epoch", "gms_map", "tcap"]

# https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/tshark/tshark.py
# def get_process_path(tshark_path=None, process_name="tshark"):
#     """Finds the path of the tshark executable.
#
#     If the user has provided a path
#     or specified a location in config.ini it will be used. Otherwise default
#     locations will be searched.
#
#     :param tshark_path: Path of the tshark binary
#     :raises TSharkNotFoundException in case TShark is not found in any location.
#     """
#     possible_paths = []
#     # Check if `config.ini` exists in the current directory or the pyshark directory
#     config = get_config()
#     if config:
#         try:
#             possible_paths.append(config.get(process_name, f"{process_name}_path"))
#         except NoSectionError:
#             pass
#
#     # Add the user provided path to the search list
#     if tshark_path is not None:
#         user_tshark_path = os.path.join(os.path.dirname(tshark_path),
#                                         f"{process_name}.exe" if sys.platform.startswith("win") else process_name)
#         possible_paths.insert(0, user_tshark_path)
#
#     # Windows search order: configuration file"s path, common paths.
#     if sys.platform.startswith("win"):
#         for env in ("ProgramFiles(x86)", "ProgramFiles"):
#             program_files = os.getenv(env)
#             if program_files is not None:
#                 possible_paths.append(
#                     os.path.join(program_files, "Wireshark", f"{process_name}.exe")
#                 )
#     # Linux, etc. search order: configuration file's path, the system's path
#     else:
#         os_path = os.getenv(
#             "PATH",
#             "/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin"
#         )
#         for path in os_path.split(":"):
#             possible_paths.append(os.path.join(path, process_name))
#     if sys.platform.startswith("darwin"):
#         possible_paths.append(f"/Applications/Wireshark.app/Contents/MacOS/{process_name}")
#
#     for path in possible_paths:
#         if os.path.exists(path):
#             if sys.platform.startswith("win"):
#                 path = path.replace("\\", "/")
#             return path
#     raise TSharkNotFoundException(
#         "TShark not found. Try adding its location to the configuration file. "
#         f"Searched these paths: {possible_paths}"
#     )
#

class TsharkExtractor:
    """Extract and process tshark messages from pcap files."""

    def __init__(self, filter_value: str, _filter=None, tshark_path=None, save_json=False, pcap_path=None):
        """Initialize TsharkExtractor.

        Args:
            _filter: Filter type to apply
            filter_value: Value to filter on
            tshark_path: Optional path to tshark executable
        """
        self.default_path = '/Applications/Wireshark.app/Contents/MacOS/tshark'
        self.tshark_path = tshark_path or self.default_path
        if not Path(self.tshark_path).exists():
            raise FileNotFoundError(f"Tshark not found at {self.tshark_path}")
        self._filter = f'{_filter}=="{filter_value}"'
        self._parser = JsonParser()
        self._save_to_file = save_json

    def scan(self, pcap: Path):
        """Scan pcap file and extract messages.

        Args:
            pcap: Path to pcap file

        Yields:
            Message objects parsed from pcap
        """
        # cmd = [self.tshark_path, "-r", str(pcap.absolute()), "-2", "-R", "gsm_map", "-Y", self._filter, "-T", "json"]
        cmd = [self.tshark_path, "-r", str(pcap.absolute()), "-Y", "gsm_map", "-T", "json"]

        # print(*cmd)
        start = datetime.datetime.now()
        # print(datetime.datetime.now())
        tshark_command_result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # print(f'exe time: {datetime.datetime.now() - start}')
        if tshark_command_result.returncode != 0:
            raise RuntimeError(f'tshark command failed. Error: \n{tshark_command_result.stderr}')
        stdout_json = json.loads(tshark_command_result.stdout)

        if self._save_to_file:
            with open(f'cached_{pcap.name}.json', 'w') as cache_file:
                json.dump(stdout_json, cache_file)

        for _frame in stdout_json:
            yield self._parser.parse_frame(_frame)


if __name__ == '__main__':
    path = Path('/Users/nikoleontiev/svyazcom/dump/p2p/case_2506/output.pcap')
    # test big file
    # path = Path('/Users/nikoleontiev/svyazcom/dump/10-04-2023_15-29-43--15-30-49.pcapng')
    test = TsharkExtractor(FilterField.MSISDN.value, filter_value='79003350276')
    # test = TsharkExtractor(msisdn='79636491816')
    for frame in test.scan(path):
        print(frame)
