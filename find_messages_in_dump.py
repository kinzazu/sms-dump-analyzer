import argparse
import os
# import lo
from tshark_search import utils
from datetime import datetime
from pathlib import Path
from tshark_search.extractor import TsharkExtractor
from tshark_search import Parser
from tshark_search import analyzer
from tshark_search.report import AsciiReporter, MarkdownReporter
from tshark_search.file_pool import FilePool
from tshark_search.models import FilterField, MsgType
from tshark_search import msgstore

ASCII_REPORT_WIDTH = 80

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--since',help="filter dump files older than this date", required=True)
    parser.add_argument('--to',help="filter dump files younger than this date", required=True)
    filters = parser.add_mutually_exclusive_group(required=True)
    filters.add_argument('--msisdn', help="select msisdn as filter and its value")
    parser.add_argument('--dump_folder', default='.', help='path to folder containing dumps')
    parser.add_argument('-r','--render',help="select render type beetween ASCII and markdown", required=True, choices=['ascii','md'])
    # filters.add_argument('--imsi', help="select imsi as filter and its value")

    # test data;
    # a = ['--dump_folder', '/Users/nikoleontiev/svyazcom/dump/p2p', '--msisdn', '79509995586']
    # return parser.parse_args(a)
    return parser.parse_args()


def get_terminal_size():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def render_report(chain, render_type):
    if render_type == 'ascii':
        report_generator = AsciiReporter(total_width=ASCII_REPORT_WIDTH)
        print(report_generator.render(chain))
    elif render_type == 'md':
        report_generator = MarkdownReporter()
        print(report_generator.render(chain))
    else:
        print(f'Unknown render type: {render_type}')


def main():
    args = parse_args()
    store = msgstore.MessageStore()
    parser = Parser.JsonParser()
    if args.dump_folder:
        fp = FilePool(args.dump_folder)
    else:
        raise ValueError('dump_folder must be specified')
    # with open('cached_output.pcap.json') as json_file:
    #     fjson = json.load(json_file)

    # for i in parser.parse_frames(fjson):
    #     print(i)

    # path = Path('/Users/nikoleontiev/svyazcom/dump/p2p/case_2506/output.pcap')
    # test big file
    # path = Path('/Users/nikoleontiev/svyazcom/dump/p2p/output.pcap')

    since = datetime.strptime(args.since, "%Y-%m-%d") if args.since else datetime.fromtimestamp(0)
    to = datetime.strptime(args.to, "%Y-%m-%d") if args.to else datetime.now()

    tshark_filter = {"start": since.timestamp(), "end":to.timestamp()}

    print(f'{since=}, {to=}')
    for file in fp.select(since=since, to=to):
        start = datetime.now()
        extractor = TsharkExtractor(date_filter=tshark_filter,
                                    pcap_path=file.filepath,
                                    save_json=False)

        for frame in extractor.scan():
            store.add(frame)

        print(f'elapsed time for {file.filepath.name}: {datetime.now() - start}')

    message_chain = analyzer.MessageChain(store, args.msisdn)
    message_chain.build()
    chain = message_chain.get_chain()

    render_report(chain, args.render)


if __name__ == '__main__':
    main()
