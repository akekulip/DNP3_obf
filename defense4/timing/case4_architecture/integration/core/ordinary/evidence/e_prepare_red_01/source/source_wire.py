"""Bounded source interpreter extension executing actual P4 deparser statements.

Checksum.update and packet_out.emit consume the parsed source field lists. This
is software source evidence, never a substitute for compiled target/model wire.
"""
from interp_ext import ExtSource, Control, checksum


class WireSource(ExtSource):
    def __init__(self, text, include_dir=None):
        super().__init__(text, include_dir)
        self.controls['IgDeparser'] = Control(self.text, 'IgDeparser')
        self.wire_output = None

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
        self.csum = {'ic': bytearray(), 'tc': bytearray()}
        self.wire_output = bytearray()
        try:
            self.apply_control('IgDeparser')
            return bytes(self.wire_output)
        finally:
            self.csum = None
            self.wire_output = None
