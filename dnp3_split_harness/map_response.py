"""
map_response.py -- decode the DNP3 header fields of a captured response frame.

No-arg run reads lab_config.py and maps a real single data frame:

    python map_response.py

Defaults: payload = payloads/baseline/data_frame.bin (falls back to the
lab_config response payload), output = reports/field_map_results.md. Or pass
``--payload`` / ``--output`` to override.

Parses a saved response payload (no L2/L3/L4 headers) into its link header
(start/length/control/addresses), the header-block CRC (validated via dnp3_crc),
the transport byte (FIR/FIN/sequence), and the application control/function/IIN,
then reports the likely first object-header offset -- to confirm which fields and
per-block CRCs any later DNP3-aware splitting or padding must preserve.
"""

import argparse
import logging
import os
import sys

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)  # so 'lab_config' / 'dnp3_crc' import regardless of cwd

import lab_config as cfg
from dnp3_crc import verify_crc

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# A real single data frame makes the cleanest field map; fall back to the
# configured response payload if it is not present.
DEFAULT_FIELD_MAP_PAYLOAD = "payloads/baseline/data_frame.bin"

# DNP3 application function codes (subset, enough to label common frames).
FUNCTION_CODES = {
    0x00: 'CONFIRM',
    0x01: 'READ',
    0x02: 'WRITE',
    0x03: 'SELECT',
    0x04: 'OPERATE',
    0x05: 'DIRECT_OPERATE',
    0x06: 'DIRECT_OPERATE_NR',
    0x0D: 'COLD_RESTART',
    0x0E: 'WARM_RESTART',
    0x14: 'ENABLE_UNSOLICITED',
    0x15: 'DISABLE_UNSOLICITED',
    0x81: 'RESPONSE',
    0x82: 'UNSOLICITED_RESPONSE',
}

# Link-layer primary function codes (when PRM=1).
LINK_PRIMARY_FUNCTIONS = {
    0x0: 'RESET_LINK_STATES',
    0x2: 'TEST_LINK_STATES',
    0x3: 'CONFIRMED_USER_DATA',
    0x4: 'UNCONFIRMED_USER_DATA',
    0x9: 'REQUEST_LINK_STATUS',
}


def _row(offset, length, field, value, meaning):
    """Build a single field-map table row."""
    return {'offset': offset, 'length': length, 'field': field,
            'value': value, 'meaning': meaning}


def parse_frame(payload):
    """
        Parse a single DNP3 frame from ``payload`` into a list of field rows.

        Parses the link header, header CRC, transport byte, and application
        header (control / function code / IIN for responses). Object parsing is
        limited to identifying the likely first object-header offset and its
        group/variation -- not full object decoding.

    :param payload: raw DNP3 TCP payload bytes (no L2/L3/L4 headers).
    :return: list of field row dicts.
    """
    rows = []
    n = len(payload)
    if n < 10:
        _log.warning('Payload too short (%s bytes) to contain a DNP3 link header.', n)
        return rows

    # ---- Link layer header (offsets 0..7) + header CRC (8..9) ----
    start = payload[0:2]
    rows.append(_row(0, 2, 'start', start.hex(),
                     'DNP3 start bytes (expect 0564)' +
                     ('' if start == b'\x05\x64' else ' [MISMATCH]')))

    length = payload[2]
    rows.append(_row(2, 1, 'length', length,
                     'LEN: octets from control byte to last user byte (excludes CRCs)'))

    ctrl = payload[3]
    dir_bit = (ctrl >> 7) & 0x1
    prm_bit = (ctrl >> 6) & 0x1
    fcb_bit = (ctrl >> 5) & 0x1
    fcv_bit = (ctrl >> 4) & 0x1
    link_func = ctrl & 0x0F
    func_name = LINK_PRIMARY_FUNCTIONS.get(link_func, 'unknown') if prm_bit else 'secondary'
    rows.append(_row(3, 1, 'link_control', '0x{:02x}'.format(ctrl),
                     'DIR={} PRM={} FCB={} FCV/DFC={} func=0x{:x} ({})'.format(
                         dir_bit, prm_bit, fcb_bit, fcv_bit, link_func, func_name)))

    dest = int.from_bytes(payload[4:6], 'little')
    rows.append(_row(4, 2, 'destination', dest, 'DNP3 destination link address (little-endian)'))
    src = int.from_bytes(payload[6:8], 'little')
    rows.append(_row(6, 2, 'source', src, 'DNP3 source link address (little-endian)'))

    header = payload[0:8]
    header_crc = payload[8:10]
    crc_ok = verify_crc(header, header_crc)
    rows.append(_row(8, 2, 'header_crc', header_crc.hex(),
                     'Link header CRC-16/DNP (little-endian); verify={}'.format(crc_ok)))

    if n < 13:
        _log.warning('Payload ends before transport/application header.')
        return rows

    # ---- Transport function byte (offset 10, first user-data octet) ----
    transport = payload[10]
    t_fin = (transport >> 7) & 0x1
    t_fir = (transport >> 6) & 0x1
    t_seq = transport & 0x3F
    rows.append(_row(10, 1, 'transport', '0x{:02x}'.format(transport),
                     'FIN={} FIR={} seq={}'.format(t_fin, t_fir, t_seq)))
    rows.append(_row(10, 1, 'transport_fir', t_fir, 'Transport First fragment bit'))
    rows.append(_row(10, 1, 'transport_fin', t_fin, 'Transport Final fragment bit'))
    rows.append(_row(10, 1, 'transport_seq', t_seq, 'Transport sequence number (0-63)'))

    # ---- Application control (offset 11) ----
    app_ctrl = payload[11]
    a_fir = (app_ctrl >> 7) & 0x1
    a_fin = (app_ctrl >> 6) & 0x1
    a_con = (app_ctrl >> 5) & 0x1
    a_uns = (app_ctrl >> 4) & 0x1
    a_seq = app_ctrl & 0x0F
    rows.append(_row(11, 1, 'app_control', '0x{:02x}'.format(app_ctrl),
                     'FIR={} FIN={} CON={} UNS={} seq={}'.format(a_fir, a_fin, a_con, a_uns, a_seq)))
    rows.append(_row(11, 1, 'app_fir', a_fir, 'Application First fragment bit'))
    rows.append(_row(11, 1, 'app_fin', a_fin, 'Application Final fragment bit'))
    rows.append(_row(11, 1, 'app_con', a_con, 'Application Confirm-requested bit'))
    rows.append(_row(11, 1, 'app_uns', a_uns, 'Application Unsolicited bit'))
    rows.append(_row(11, 1, 'app_seq', a_seq, 'Application sequence number (0-15)'))

    # ---- Application function code (offset 12) ----
    func = payload[12]
    func_name = FUNCTION_CODES.get(func, 'unknown')
    rows.append(_row(12, 1, 'function_code', '0x{:02x}'.format(func),
                     'Application function: {}'.format(func_name)))

    # ---- IIN (responses only) and likely object header offset ----
    obj_offset = 13
    if func in (0x81, 0x82) and n >= 15:
        iin = payload[13:15]
        rows.append(_row(13, 2, 'iin', iin.hex(),
                         'Internal Indications (response only); IIN1=0x{:02x} IIN2=0x{:02x}'.format(
                             iin[0], iin[1])))
        obj_offset = 15

    # Objects are present only if this frame's user data extends past the
    # application header. LEN (offset 2) counts ctrl+dest+src (5) + user bytes;
    # a response header consumes through IIN (LEN must exceed 10), a request
    # header through the function code (LEN must exceed 8). Otherwise the bytes
    # at obj_offset are a data-block CRC, not an object header.
    has_objects = (length > 10) if func in (0x81, 0x82) else (length > 8)
    if has_objects and n > obj_offset + 1:
        grp = payload[obj_offset]
        var = payload[obj_offset + 1]
        rows.append(_row(obj_offset, 2, 'object_header',
                         'g{}v{}'.format(grp, var),
                         'First object header: group={} variation={}'.format(grp, var)))
    else:
        rows.append(_row(obj_offset, 0, 'object_header', 'none',
                         'No object data in this frame (LEN={} is header-only)'.format(length)))

    return rows


def render_markdown(rows, payload_len, source_path):
    """Render the parsed field rows as a Markdown document with a table."""
    lines = []
    lines.append('# DNP3 Field Map')
    lines.append('')
    lines.append('Source payload: `{}` ({} bytes)'.format(source_path, payload_len))
    lines.append('')
    lines.append('> Parsing covers the link header, header CRC, transport byte, and')
    lines.append('> application header. Object decoding is limited to identifying the')
    lines.append('> first object-header offset (group/variation), not full objects.')
    lines.append('')
    lines.append('| offset | length | field | value | meaning |')
    lines.append('|---|---|---|---|---|')
    for r in rows:
        lines.append('| {} | {} | {} | {} | {} |'.format(
            r['offset'], r['length'], r['field'], r['value'], r['meaning']))
    lines.append('')
    return '\n'.join(lines)


def build_parser():
    """Build the argument parser; defaults come from lab_config.py."""
    parser = argparse.ArgumentParser(
        description='Map DNP3 link/transport/application header fields from a raw payload .bin.')
    parser.add_argument('--payload', default=None,
                        help='Raw DNP3 payload .bin (default: data_frame.bin, else lab_config payload).')
    parser.add_argument('--output', default=os.path.join(cfg.REPORT_DIR, 'field_map_results.md'),
                        help='Path to write the Markdown field map.')
    return parser


def main():
    args = build_parser().parse_args()

    # Resolve the payload: explicit flag, else data_frame.bin, else lab_config payload.
    payload_path = args.payload
    if payload_path is None:
        payload_path = DEFAULT_FIELD_MAP_PAYLOAD
        if not os.path.exists(os.path.join(HARNESS_DIR, payload_path)):
            payload_path = cfg.DEFAULT_RESPONSE_PAYLOAD
    abs_payload = (payload_path if os.path.isabs(payload_path)
                   else os.path.join(HARNESS_DIR, payload_path))
    if not os.path.exists(abs_payload):
        _log.error('Payload not found: %s. Extract payloads first.', abs_payload)
        sys.exit(1)

    output = args.output if os.path.isabs(args.output) else os.path.join(HARNESS_DIR, args.output)

    with open(abs_payload, 'rb') as fh:
        payload = fh.read()

    rows = parse_frame(payload)
    markdown = render_markdown(rows, len(payload), payload_path)

    out_dir = os.path.dirname(os.path.abspath(output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output, 'w') as fh:
        fh.write(markdown)

    _log.info('Wrote field map (%s fields) to %s', len(rows), output)


if __name__ == '__main__':
    main()
