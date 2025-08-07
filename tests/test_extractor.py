# ../dump_analyzer/tests/test_extractor.py
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from msg_trace.Parser import JsonParser
from msg_trace.extractor import TsharkExtractor


class TestTsharkExtractor(unittest.TestCase):

    def setUp(self):
        self.mock_parser = MagicMock(spec=JsonParser)
        self.tshark_extractor = TsharkExtractor(
            date_filter={"start": datetime.fromtimestamp(0).timestamp(), "end":datetime.now().timestamp()},
            tshark_path="/usr/bin/tshark",
            save_json=False,
            pcap_path=None
        )
        self.tshark_extractor._parser = self.mock_parser

    def test_initialization_tshark_not_found(self):
        with self.assertRaises(FileNotFoundError):
            TsharkExtractor(
                date_filter={"start": datetime.fromtimestamp(0).timestamp(), "end": datetime.now().timestamp()},
                tshark_path="/invalid/path/to/tshark",
                save_json=False,
                pcap_path=None
            )

    @patch("subprocess.run")
    def test_scan_successful(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = b'[{"frame": "test_frame"}]'
        self.mock_parser.parse_frame.return_value = "parsed_message"
        results = list(self.tshark_extractor.scan(Path("/path/to/file.pcap")))
        self.assertEqual(["parsed_message"], results)

    @patch("subprocess.run")
    def test_scan_subprocess_failure(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 1
        mock_subprocess_run.return_value.stderr = b"Error occurred"
        with self.assertRaises(RuntimeError) as context:
            list(self.tshark_extractor.scan(Path("/path/to/file.pcap")))
        self.assertIn("tshark command failed", str(context.exception))

    @patch("subprocess.run")
    def test_save_to_file(self, mock_subprocess_run):
        tshark_extractor = TsharkExtractor(
            filter_value="test_value",
            _filter="test_filter",
            tshark_path="/usr/bin/tshark",
            save_json=True,
            pcap_path=None
        )
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = b'[{"frame": "test_frame"}]'
        with patch("builtins.open", unittest.mock.mock_open()) as mock_file:
            list(tshark_extractor.scan(Path("/path/to/file.pcap")))
            mock_file.assert_called_once_with("cached_file.pcap.json", "w")

    @patch("subprocess.run")
    def test_scan_parser_called(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = b'[{"frame": "test_frame_1"}, {"frame": "test_frame_2"}]'
        self.mock_parser.parse_frame.side_effect = ["message_1", "message_2"]
        results = list(self.tshark_extractor.scan(Path("/path/to/file.pcap")))
        self.assertEqual(["message_1", "message_2"], results)
        self.mock_parser.parse_frame.assert_any_call({"frame": "test_frame_1"})
        self.mock_parser.parse_frame.assert_any_call({"frame": "test_frame_2"})


if __name__ == "__main__":
    unittest.main()
