"""Bounded source interpreter extension executing actual P4 deparser statements.

Checksum.update and packet_out.emit consume the parsed source field lists. This
is software source evidence, never a substitute for compiled target/model wire.
"""
import re
from interp_ext import ExtSource, Control, checksum


class WireSource(ExtSource):
    def __init__(self, text, include_dir=None):
        text = re.sub(r"\bmirror\.emit<\w+>", "mirror.emit", text)
        super().__init__(text, include_dir)
        self.controls['IgDeparser'] = Control(self.text, 'IgDeparser')
        self.wire_output = None
        self.mirror_headers = []
        self.in_mirror = False

    def ev(self, node):
        if self.in_mirror and node[0] == 'name' and node[1].startswith('hdr.'):
            name = node[1].split('.')[1]
            if not self.valid.get(name, False):
                raise ValueError('undefined invalid-header Mirror input: ' + node[1])
        return super().ev(node)

    def call(self, path, args, node=None):
        if path == 'mirror.emit':
            self.in_mirror = True
            try:
                self.mirror_headers.append((self.ev(args[0])[0], self.csum_bytes(args[1])))
            finally:
                self.in_mirror = False
            return 0, None
        return super().call(path, args, node)

    def csum_call(self, owner, method, args):
        if method == 'update':
            return checksum(self.csum_bytes(args[0])), 16
        return super().csum_call(owner, method, args)

    def pkt_call(self, method, args):
        if method == 'emit' and self.wire_output is not None:
            header = args[0][1]
            names = self.header_order if header == 'hdr' else [header.split('.')[1]]
            for name in names:
                if self.valid.get(name, False):
                    self.wire_output.extend(self.render(name))
            return 0, None
        return super().pkt_call(method, args)

    def render_wire(self):
        self.mirror_headers = []
        self.csum = {'ic': bytearray(), 'tc': bytearray()}
        self.wire_output = bytearray()
        try:
            self.apply_control('IgDeparser')
            return bytes(self.wire_output)
        finally:
            self.csum = None
            self.wire_output = None
