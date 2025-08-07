import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from msg_trace.Parser import JsonParser
from msg_trace.models import Message, MsgType, TCAPState


class TestJsonParser(unittest.TestCase):
    def setUp(self):
        self.parser = JsonParser()

    @patch.object(JsonParser, '_frame_to_msg')
    def test_parse_frame_calls_frame_to_msg(self, mock_frame_to_msg):
        mock_frame = {"_source": {"layers": {}}}
        mock_message = Message()
        mock_frame_to_msg.return_value = mock_message

        result = self.parser.parse_frame(mock_frame)

        mock_frame_to_msg.assert_called_once_with(mock_frame)
        self.assertEqual(mock_message, result)

    @patch.object(JsonParser, '_frame_to_msg')
    def test_parse_frames_yields_expected_messages(self, mock_frame_to_msg):
        mock_frames = [{"_source": {"layers": {}}}, {"_source": {"layers": {}}}]
        mock_message_1 = Message()
        mock_message_2 = Message()
        mock_frame_to_msg.side_effect = [mock_message_1, mock_message_2]

        results = list(self.parser.parse_frames(mock_frames))

        self.assertEqual([mock_message_1, mock_message_2], results)

    def test_fill_tcap_begin(self):
        tcap_json = {
            "tcap.begin_element": {
                "tcap.tid": "transaction_id_123"
            }
        }

        tid, tcap_state = self.parser._fill_tcap(tcap_json)

        self.assertEqual("transaction_id_123", tid)
        self.assertEqual(TCAPState.Begin, tcap_state)

    def test_fill_tcap_empty_tcap_json_raises_runtime_error(self):
        tcap_json = {}

        with self.assertRaises(RuntimeError):
            self.parser._fill_tcap(tcap_json)

    @patch.object(JsonParser, '_fix_tp_da_key')
    def test_fill_sms_fields_normalizes_keys(self, mock_fix_tp_da_key):
        sms_json = {"gsm_sms.tp-mti": "0"}
        mock_msg = Message()
        mock_fix_tp_da_key.return_value = sms_json

        result = self.parser._fill_sms_fields(sms_json, mock_msg)

        mock_fix_tp_da_key.assert_called_once_with(sms_json)
        self.assertEqual(mock_msg, result)

    def test_gms_opcode_from_invoke_extracts_opcode(self):
        invoke_json = {"gsm_old.opCode_tree": {"gsm_old.localValue": "45"}}

        result = self.parser._gms_opcode_from_invoke(invoke_json)

        self.assertEqual(MsgType.SRI, result)

    def test_gms_opcode_from_invoke_raises_runtime_error_for_empty_tree(self):
        invoke_json = {}

        with self.assertRaises(RuntimeError):
            self.parser._gms_opcode_from_invoke(invoke_json)


if __name__ == "__main__":
    unittest.main()
