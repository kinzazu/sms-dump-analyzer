# Dump Analyzer

A Python tool for analyzing network packet dumps containing GSM MAP protocol data, with a focus on SMS messaging. This tool extracts, parses, and visualizes message chains from pcap files, making it easier to trace and debug telecommunications signaling.

## Features

- Extract GSM MAP protocol messages from pcap/pcapng files
- Filter messages by MSISDN (phone number) ~~or IMSI~~(this feature will be available later)
- Parse and analyze message chains
- Generate ASCII-based visual reports of message flows or markdown report with `mermaid` diagramming and charting tool.
- Support for various MAP operation codes related to SMS services

## Prerequisites

- Python 3.11 or higher
- Wireshark/tshark installed on your system

### Wireshark/tshark Installation

#### macOS
```bash
# Using Homebrew
brew install wireshark
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt install wireshark 
# for tshark and other cli utils without Wireshark run:
sudo apt install wireshark-cli 
```

## Project Setup

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/dump_analyzer.git
   cd dump_analyzer
   ```

2. No formal dependency management is in place, but the project primarily uses standard Python libraries

3. The main external dependency is `tshark`, which must be installed separately as described above

## Configuration

The project uses hardcoded paths in some places. Key configuration points:

- In `tshark_search/extractor.py`, the default path for tshark on macOS is set to `/Applications/Wireshark.app/Contents/MacOS/tshark`
- You can override this by providing a custom path when initializing the `TsharkExtractor` class

## Usage

### Basic Usage

```bash
python find_messages_in_dump.py --dump_folder /path/to/dumps --msisdn 79999999999
```

### Command Line Arguments

- `--dump_folder`: Path to folder containing dump files (default: current directory)
- `--since`: Filter dump files older than this date
- `--to`: Filter dump files younger than this date
- `--msisdn`: Filter by MSISDN (phone number)
- `--imsi`: Filter by IMSI

### Example

```bash
# Find all messages related to a specific phone number
python find_messages_in_dump.py --dump_folder /path/to/dumps --msisdn 79001234567

# Find all messages related to a specific IMSI
python find_messages_in_dump.py --dump_folder /path/to/dumps --imsi 250991234567890
```

## Project Structure

- `find_messages_in_dump.py`: Main entry point for the application
- `tshark_search/`: Core package containing modules for parsing and analyzing network dumps
  - `Parser.py`: Parses JSON output from tshark
  - `analyzer.py`: Analyzes parsed messages
  - `extractor.py`: Extracts data from pcap files using tshark
  - `models.py`: Defines data models for the application
  - `msgstore.py`: Stores and manages message data
  - `report.py`: Generates reports from the analyzed data
  - `utils.py`: Utility functions

## Message Flow

The application processes network dumps in the following steps:

1. `TsharkExtractor` extracts data from pcap files using tshark
2. The extracted data is parsed using `JsonParser`
3. Parsed messages are stored in a `MessageStore`
4. Messages are analyzed using `MessageChain`
5. Reports are generated using `AsciiReporter`

## Testing

The project uses Python's standard `unittest` framework for testing.

### Running Tests

To run all tests:
```bash
python -m unittest discover tests
```

To run a specific test file:
```bash
python -m unittest tests/test_models.py
```

To run a specific test case:
```bash
python -m unittest tests.test_models.TestMessage.test_message_creation
```

## Debugging

- The application can save extracted JSON data to a file for debugging purposes by setting `save_json=True` when initializing `TsharkExtractor`
- You can run individual components separately for debugging (see the `__main__` blocks in various modules)

## Example Output

The ASCII reporter generates a visual representation of message chains like this:

```
│─────────────────────────────────────Subscriber: 79999999999 ─────────────────────────────────────│
OPC: 14685                                                                                DPC: 10521
│                                                                                                  │
│ 25/03 08:26:23                                                                                   │
├───────────────────── MO_Forward_SM   TID=00:49:00:44    MSISDN=79999999999 ─────────────────────▶│
│ 25/03 08:26:25                                                                                   │
│◀───────────────────────── ResultLast      TID=00:49:00:44    IMSI=None ──────────────────────────┤
│ 25/03 08:26:25                                                                                   │
├───────────────────── SRI             TID=2f:7a:c6:22    MSISDN=79999999999 ─────────────────────▶│
│ 25/03 08:26:26                                                                                   │
│◀───────────────────────── ResultLast      TID=2f:7a:c6:22    IMSI=None ──────────────────────────┤
│ 25/03 08:27:26                                                                                   │
├───────────────────── SRI             TID=2f:94:5e:3e    MSISDN=79999999999 ─────────────────────▶│
│ 25/03 08:27:26                                                                                   │
```
