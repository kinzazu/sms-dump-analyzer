import unittest
from datetime import datetime, timedelta
from pathlib import Path

from tshark_search.capinfo import CapInfo
from tshark_search.file_pool import FilePool


class TestFilePool(unittest.TestCase):
    def setUp(self):
        # Set up a test instance with a mock folder
        self.test_folder = "/tmp/test_dumps"
        self.file_pool = FilePool(self.test_folder)

    def test_repr(self):
        # Test if __repr__ returns the expected string format
        repr_string = repr(self.file_pool)
        expected_prefix = f"{self.test_folder} :"
        self.assertTrue(repr_string.startswith(expected_prefix))

    def test_add_file(self):
        # Test if a file is correctly added to the pool
        test_file_path = Path("/tmp/test_dumps/sample.pcap")
        capinfo_mock = CapInfo(test_file_path)
        self.file_pool.add_file = lambda file_path: self.file_pool._files.add(capinfo_mock)

        self.file_pool.add_file(test_file_path)
        self.assertEqual(1, len(self.file_pool._files))

    def test_select(self):
        # Test if select method filters files based on time range
        start_time = datetime.now()
        end_time = start_time + timedelta(hours=1)

        # Mock CapInfo objects with overlapping and non-overlapping time ranges
        capinfo_mock_1 = CapInfo("file1")
        capinfo_mock_1.ts_start = start_time - timedelta(minutes=30)
        capinfo_mock_1.ts_end = start_time + timedelta(minutes=30)

        capinfo_mock_2 = CapInfo("file2")
        capinfo_mock_2.ts_start = end_time + timedelta(minutes=1)
        capinfo_mock_2.ts_end = end_time + timedelta(minutes=10)

        self.file_pool._files = {capinfo_mock_1, capinfo_mock_2}
        result = list(self.file_pool.select(start_time, end_time))

        self.assertEqual(1, len(result))
        self.assertEqual(capinfo_mock_1, result[0])

    def test_process_to_path(self):
        # Test if _process_to_path method decodes string paths correctly
        processed_path = self.file_pool._process_to_path("~/test_folder")
        expected_path = Path("~/test_folder").expanduser()
        self.assertEqual(expected_path, processed_path)


if __name__ == "__main__":
    unittest.main()
