"""Cover-frame TCP injector (TEST INSTRUMENT, not an obfuscation product).

A transparent loopback relay between a real OpenDNP3 master (connects here) and a real OpenDNP3
outstation (real TCP server). It forwards every byte verbatim in both directions. In the
master->outstation direction ONLY, whenever a forwarded chunk begins at a DNP3 frame boundary
(0x05 0x64), it PREPENDS one pre-built, CRC-valid DNP3 cover link frame addressed to a chosen
link address. It never edits a real DNP3 byte and never recomputes a real CRC; the cover is a
standalone valid frame inserted into the stream. Purpose: observe whether the real outstation's
link layer discards the cover (individual address) or accepts it (broadcast) while the live
transaction runs.

Args:  LISTEN_PORT  OUTSTATION_PORT  COVER_DEST(int)  COVER_LABEL
Env:   INJ_STOP_AFTER_S (default 6)
"""
import asyncio
import sys

def dnp3_crc16(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFF

def build_user_data_frame(from_master: bool, dest: int, src: int, ud: bytes) -> bytes:
    ctrl = 0x40 | 0x04           # PRM=1, Unconfirmed User Data (func 4)
    if from_master:
        ctrl |= 0x80             # DIR
    length = 5 + len(ud)
    hdr = bytes([0x05, 0x64, length, ctrl,
                 dest & 0xFF, (dest >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF])
    out = bytearray(hdr)
    hcrc = dnp3_crc16(hdr)
    out += bytes([hcrc & 0xFF, (hcrc >> 8) & 0xFF])
    for i in range(0, len(ud), 16):
        block = ud[i:i + 16]
        bcrc = dnp3_crc16(block)
        out += block + bytes([bcrc & 0xFF, (bcrc >> 8) & 0xFF])
    return bytes(out)

# Cover APDU: transport 0xC0 + READ class-1 marker (C0 01 3C 01 06)
COVER_UD = bytes([0xC0, 0xC0, 0x01, 0x3C, 0x01, 0x06])

LISTEN_PORT = int(sys.argv[1])
OUT_PORT = int(sys.argv[2])
COVER_DEST = int(sys.argv[3])
COVER_LABEL = sys.argv[4]
COVER_FRAME = build_user_data_frame(True, COVER_DEST, 1, COVER_UD)

covers_injected = 0

async def pipe(reader, writer, inject: bool):
    global covers_injected
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            if inject and chunk[:2] == b"\x05\x64":
                writer.write(COVER_FRAME)   # prepend a valid cover at the frame boundary
                covers_injected += 1
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def handle(client_reader, client_writer):
    out_reader, out_writer = await asyncio.open_connection("127.0.0.1", OUT_PORT)
    await asyncio.gather(
        pipe(client_reader, out_writer, inject=True),    # master -> outstation (inject covers)
        pipe(out_reader, client_writer, inject=False),   # outstation -> master (verbatim)
    )

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", LISTEN_PORT)
    stop_after = float(__import__("os").environ.get("INJ_STOP_AFTER_S", "6"))
    async with server:
        try:
            await asyncio.wait_for(server.serve_forever(), timeout=stop_after)
        except asyncio.TimeoutError:
            pass
    print(f'{{"cover_label":"{COVER_LABEL}","cover_dest":{COVER_DEST},'
          f'"cover_frame_len":{len(COVER_FRAME)},"covers_injected":{covers_injected}}}')

asyncio.run(main())
