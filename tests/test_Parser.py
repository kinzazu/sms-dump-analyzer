import unittest
from datetime import datetime, timezone

# NOTE: the tests are now run as part of the 'tshark_search' package,
# so absolute imports work without manipulating sys.path.
from tshark_search.Parser import JsonParser
from tshark_search.models import MsgType, TCAPState


class TestJsonParser(unittest.TestCase):
    def setUp(self):
        self.parser = JsonParser()

    def test_parse_frame_begin_element(self):
        test_frame = {
            "_source": {
                "layers": {
                    "frame": {"frame.time_epoch": "1750825516.923860000"},
                    "tcap": {"tcap.begin_element": {"tcap.tid": "09:eb:27:bb"}},
                    "gsm_map": {
                        "gsm_map.old.Component_tree": {
                            "gsm_old.invoke_element": {
                                "gsm_old.opCode_tree": {"gsm_old.localValue": "45"},
                                "gsm_map.sm.msisdn_tree": {"e164.msisdn": "79003350829"},
                            }
                        }
                    },
                }
            }
        }

        message = self.parser.parse_frame(test_frame)

        self.assertEqual("09:eb:27:bb", message.tid)
        self.assertEqual(message.tcap_state, TCAPState.Begin)
        self.assertEqual(message.opcode, MsgType.SRI)
        self.assertEqual(message.msisdn, "79003350829")
        self.assertEqual(1750825516.923860000, message.time, )
        # self.assertEqual(
        #     message.time, datetime.fromtimestamp(1750825516.923860000).astimezone(timezone.utc)
        # )

    def test_parse_frame_end_element(self):
        test_frame = {
            "_source": {
                "layers": {
                    "frame": {"frame.time_epoch": ["1750825516.924632000"]},
                    "tcap": {"tcap.end_element": {"tcap.tid": "09:eb:27:bb"}},
                    "gsm_map": {
                        "gsm_map.old.Component_tree": {
                            "gsm_old.returnResultLast_element": {"e212.imsi": "84851502726718"}
                        }
                    },
                }
            }
        }

        message = self.parser.parse_frame(test_frame)

        self.assertEqual(message.tid, "09:eb:27:bb")
        self.assertEqual(message.tcap_state, TCAPState.End)
        self.assertEqual(message.opcode, MsgType.ResultLast)
        self.assertEqual(message.imsi, "84851502726718")
        self.assertEqual(message.time, 1750825516.924632000)

    def test_parse_frames_multiple_entries(self):
        test_frames = [
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.time_epoch": ["1750825516.923860000"]},
                        "tcap": {"tcap.begin_element": {"tcap.tid": "09:eb:27:bb"}},
                        "gsm_map": {
                            "gsm_map.old.Component_tree": {
                                "gsm_old.invoke_element": {
                                    "gsm_old.opCode_tree": {"gsm_old.localValue": "45"},
                                    "gsm_map.sm.msisdn_tree": {"e164.msisdn": "79003350829"},
                                }
                            }
                        },
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.time_epoch": ["1750825516.924632000"]},
                        "tcap": {"tcap.end_element": {"tcap.tid": "09:eb:27:bb"}},
                        "gsm_map": {
                            "gsm_map.old.Component_tree": {
                                "gsm_old.returnResultLast_element": {"e212.imsi": "84851502726718"}
                            }
                        },
                    }
                }
            },
        ]

        messages = list(self.parser.parse_frames(test_frames))

        # first message
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].tid, "09:eb:27:bb")
        self.assertEqual(messages[0].tcap_state, TCAPState.Begin)
        self.assertEqual(messages[0].opcode, MsgType.SRI)
        self.assertEqual(messages[0].msisdn, "79003350829")
        self.assertEqual(
            messages[0].time,
            datetime.fromtimestamp(1750825516.923860000).astimezone(timezone.utc),
        )

        # second message
        self.assertEqual(messages[1].tid, "09:eb:27:bb")
        self.assertEqual(messages[1].tcap_state, TCAPState.End)
        self.assertEqual(messages[1].opcode, MsgType.ResultLast)
        self.assertEqual(messages[1].imsi, "84851502726718")
        self.assertEqual(
            messages[1].time,
            datetime.fromtimestamp(1750825516.924632000).astimezone(timezone.utc),
        )


if __name__ == "__main__":
    unittest.main()