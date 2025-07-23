import subprocess
from pathlib import Path
from datetime import datetime

class CapInfo:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.ts_start = None
        self.ts_end = None
        self.duration = None
        self.frames = None


    @classmethod
    def form_info(cls, pcap_path, capinfos_cmd='capinfos'):
        """
        Create a capinfos instance from a pcap file using capinfos utility.
        :param pcap_path:
        :param capinfos_cmd:
        :return: CapInfos
        """
        obj = cls(pcap_path)

        # option description
        # -a start -e end -S Unix timestamp in format -T table output, -r without header -m separated my comma
        cmd = f'{capinfos_cmd} -S -a -e -T -r -m -c {pcap_path}'

        proc = subprocess.run(cmd, shell=True,capture_output= True, text=True)

        if proc.returncode != 0:
            raise RuntimeError(f'capinfos error {proc.returncode}: {proc.stderr.strip()}')

        capinfos_output = proc.stdout.strip()
        capinfos_output = capinfos_output.split(',')
        # print(capinfos_output)

        obj.filepath = Path(capinfos_output[0])
        obj.frames = int(capinfos_output[1])
        obj.ts_start = datetime.fromtimestamp(float(capinfos_output[2]))
        obj.ts_end = datetime.fromtimestamp(float(capinfos_output[3]))
        obj.duration = obj.ts_end - obj.ts_start

        return obj

    def __repr__(self):
        # Show only file name not full path -> filepath.name
        return f'<CapInfos({self.filepath.name}), {self.frames=} {self.ts_start=} {self.ts_end=}>'

