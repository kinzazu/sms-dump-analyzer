import argparse
import os
from datetime import datetime
from tshark_search.src import TsharkExtractor
from tshark_search.src import FilePool

# FIELDS = ["frame.time.epoch", "gms_old.opCode", "e164.msisdn", "tcap.tid", "e212.imsi"]
# def run_tshark(pcap: str, disp_filter: str = "") -> Iterable[list[str]]:
#     cmd = ["tshark", "-r", pcap, "-Y", disp_filter, "-T", "fields"]
#     for f in FIELDS:
#         cmd += ["-e", f]
#         cmd += ["-E", "header=n", "-E", "separator=,"]
#         with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
#             for line in proc.stdout: yield line.rstrip("\n").split(",")



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dump_folder', required=True)
    parser.add_argument('--since',help="")
    parser.add_argument('--to',help="")
    parser.add_argument('--msisdn', help="")
    parser.add_argument('--imsi', help="")

    # test data;
    a = ['--dump_folder', '/Users/nikoleontiev/svyazcom/dump/p2p', '--msisdn', '79509995586']
    return parser.parse_args(a)

def check_os():
    v = os.uname()
    return v.sysname

def actions_based_on_os():
    match check_os():
        case 'Darwin':
            print('You are using Mac OS X')

        case 'Linux':
            print('You are using Linux')
            print('To install Tshark you need to install wireshark-cli package')
            print('ex. for Ubuntu: `sudo apt install wireshark-cli`')

def main():
    actions_based_on_os()
    args = parse_args()

    since = datetime.fromisoformat(args.since) if args.since else datetime.min
    to    = datetime.fromisoformat(args.to)    if args.to    else datetime.max

    pool = FilePool(args.dump_folder)
    extractor = TsharkExtractor(args.msisdn)
    analyzer = Analyzer()

    for meta in pool.select(since, to):
        for msg in extractor.scan(meta.filepath):
            analyzer.feed(msg)

    reporter = AsciiReporter()
    for tx in analyzer.transactions():
        print(reporter.render(tx))
        print("-" * 40)


    # for root, file in file_generator:
    #     full_path = root + '/' + file
    #     cmd = ['/Applications/Wireshark.app/Contents/MacOS/capinfos','-a','-e','-T','-r','-m', f'{full_path}']
    #     res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    #     if res.returncode == 0:
    #         result = res.stdout.decode('utf-8').split('\n')
    #         billet = {}
    #         for line in result:
    #            file, first_packet, last_packet = line.split(',')


if __name__ == '__main__':
    main()
