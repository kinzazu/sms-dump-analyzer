import datetime
# from enum import Enum
from pathlib import Path

from src.Parser import JsonParser
from src.models import FilterField
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


"""
cache implementation:
add .meta for filter information and output file for this filters.
for ex. it will be json file
    .meta.json:
    [ "since": "1970-0-0"    # time string
      "to": "12039871237868" # timestamp
      "msisdn": "1234907918"
    ]
 
  
If executed program contain same filter then use cache file else use `TsharkExtractor`

"""

class TsharkExtractor:
    """Extract and process tshark messages from pcap files."""

    def __init__(self, date_filter:dict , tshark_path='tshark', save_json=False, pcap_path=None):
        """Initialize TsharkExtractor.

        Args:
            _filter: Filter type to apply
            filter_value: Value to filter on
            tshark_path: Optional path to tshark executable
        """
        self.tshark_path = tshark_path
        self._date_filter = date_filter
        self._parser = JsonParser()
        self._save_to_file = save_json
        self._pcap_file = pcap_path

    def scan(self):
        """
        Scan a pcap file and extract Message objects by the Parser object.

        Yields:
            Message objects parsed from pcap
        """
        start = self._date_filter.get("start")
        end = self._date_filter.get("end")

        # cmd = [self.tshark_path, "-r", str(pcap.absolute()), "-2", "-R", "gsm_map", "-Y", self._filter, "-T", "json"]
        cmd = [self.tshark_path, "-r", str(self._pcap_file.absolute()), "-2","-R",
               f"frame.time_epoch >={start} and frame.time_epoch <={end} ", "-Y", "gsm_map", "-T", "json"
              ]

        tshark_command_result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # print(f'exe time: {datetime.datetime.now() - start}')
        if tshark_command_result.returncode != 0:
            raise RuntimeError(f'tshark command failed. Error: \n{tshark_command_result.stderr}')
        stdout_json = json.loads(tshark_command_result.stdout)

        if self._save_to_file:
            with open(f'cached_{self._pcap_file.name}.json', 'w') as cache_file:
                json.dump(stdout_json, cache_file)

        for _frame in stdout_json:
            yield self._parser.parse_frame(_frame)
