"""
Lab-wide configuration for the DNP3 replay/split experiment.

Update these values once if the lab roles change. The point of this file is so
the user never has to type IP addresses in manual commands: the three runner
scripts (run_outstation.py / run_master.py / split_server.py) and the
convenience wrappers all read their defaults from here.

If the lab roles are reversed, edit only this file -- not every command.
"""

# Based on the captured DNP3 session:
#   10.10.54.19 used the ephemeral TCP client port  -> it is the master.
#   10.10.54.158 listened on TCP/20000              -> it is the outstation.
MASTER_IP = "10.10.54.19"
OUTSTATION_IP = "10.10.54.158"

# In the replay/split phase, the split server replaces the outstation, so it
# runs at the outstation's address/port and the master command does not change.
SPLIT_SERVER_IP = OUTSTATION_IP

# Servers bind to all interfaces on their host.
BIND_IP = "0.0.0.0"

DNP3_PORT = 20000

# DNP3 link-layer addresses.
MASTER_LINK_ADDR = 1
OUTSTATION_LINK_ADDR = 10

# Default experiment behavior.
DEFAULT_RESPONSE_TIMEOUT_SEC = 2
DEFAULT_WAIT_AFTER_ACTION_SEC = 5
# CRC-boundary split: cut the captured stream only on existing DNP3 CRC block
# boundaries so every chunk ends on an already-valid CRC. No CRC is recomputed
# and no byte is altered (concatenation == original). Maps to the split server's
# "crc" mode; "crc-boundary" is accepted as the descriptive alias.
DEFAULT_SPLIT_MODE = "crc-boundary"
DEFAULT_BLOCKS_PER_CHUNK = 1
DEFAULT_CHUNK_DELAY_MS = 10
DEFAULT_HOLD_AFTER_RESPONSE_SEC = 20

# Default local sub-directories (relative to this harness directory).
CAPTURE_DIR = "captures"
PAYLOAD_DIR = "payloads"
LOG_DIR = "logs"
REPORT_DIR = "reports"

# split_server.py is THE canonical request-aware TCP replay/split server: it
# reassembles whole DNP3 frames from the TCP stream, parses each request's
# function code + app sequence, replies with ONLY its matching captured response,
# splits every data RESPONSE (the READ fragment AND its CONFIRM-triggered
# continuation) on existing CRC boundaries, waits for the master CONFIRM, and
# refuses to fire a captured response at a request it cannot match.
#   --delivery full          -- exact verbatim replay (one write per response)
#   --delivery crc-boundary  -- byte-preserving CRC split (default)
# The superseded standalone servers (exact / ordered / legacy single-shot) and
# the dnp3_crc_splitter.py CLI now live under archive_experiments/ for reference.

# Directory of captured responses (orig_*.bin / resp_*.bin + metadata.json)
# extracted from the OUTSTATION-side baseline capture
# (captures/baseline/Hulk_outstation.pcapng). Used to reconstruct the captured
# request->response exchange.
DEFAULT_REPLAY_DIR = "payloads/replay"

# Default single-response payload for "single" mode.
#   resp_0001 is only a 17-byte link response; the validated full multi-fragment
#   READ response (9 link frames / 2407 B) is the meaningful payload, so we
#   default single mode to it.
DEFAULT_RESPONSE_PAYLOAD = "payloads/from_live/read_response_full.bin"

# Default baseline capture used by extract_payloads.py / map_response.py /
# analyze_ack.py.
DEFAULT_CAPTURE = "captures/baseline/read_exchange.pcap"

# For large response generation by run_outstation.py.
DEFAULT_DB_SIZE = 300
DEFAULT_NUM_ANALOG = 200
DEFAULT_NUM_BINARY = 50
DEFAULT_NUM_COUNTER = 50
