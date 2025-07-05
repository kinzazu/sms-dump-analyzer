from datetime import datetime
from pathlib import Path
from tshark_search.extractor import TsharkExtractor
from tshark_search import Parser
from tshark_search.report import AsciiReporter
import json
from tshark_search.models import FilterField
from tshark_search import msgstore



store = msgstore.MessageStore()

# def main(): pass





if __name__ == '__main__':
    parser = Parser.JsonParser()
    with open('cached_output.pcap.json') as json_file:
        fjson = json.load(json_file)

    # for i in parser.parse_frames(fjson):
    #     print(i)

    # path = Path('/Users/nikoleontiev/svyazcom/dump/p2p/case_2506/output.pcap')
    # test big file
    path = Path('/Users/nikoleontiev/svyazcom/dump/p2p/output.pcap')
    test = TsharkExtractor(_filter=FilterField.MSISDN.value,
                           filter_value='79636491816',
                           pcap_path=path,
                           save_json=False)

    c = 0


    start = datetime.now()
    for frame in test.scan(path):
    # for frame in parser.parse_frames(fjson):
        c += 1
        # print(f'{c:<4} :{frame}')
        store.add(frame)
    # for frame in test.scan(path):
    #     print(frame)
    end = datetime.now()
    a = end - start
    print(f'total frames: {c=} elapsed time: {a.total_seconds()}')
    print(store.by_tid('47:6b:c9:c3'))