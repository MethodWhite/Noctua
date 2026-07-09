import struct
from .base import BinaryLoader


MACHO_MAGICS = {
    0xfeedface: (False, False),
    0xcefaedfe: (False, True),
    0xfeedfacf: (True, False),
    0xcffaedfe: (True, True),
}


class MachOLoader(BinaryLoader):
    name = "macho"

    @classmethod
    def check(cls, data):
        magic = struct.unpack("<I", data[:4])[0]
        if magic in MACHO_MAGICS:
            return True
        magic_be = struct.unpack(">I", data[:4])[0]
        return magic_be in MACHO_MAGICS

    @classmethod
    def load(cls, data, engine):
        loader = cls()
        loader.data = data
        loader.engine = engine
        loader._parse_header()
        loader._parse_load_commands()
        loader._extract_sections()
        loader._detect_cpu()
        engine.loader = loader
        engine.macho = loader
        return loader

    def _parse_header(self):
        data = self.data
        magic = struct.unpack("<I", data[:4])[0]
        self.is_64, self.swap = MACHO_MAGICS.get(magic, (False, False))
        if self.swap:
            endian = ">"
        else:
            endian = "<"
        self.endian = endian
        if self.is_64:
            fmt = endian + "IIIIII"
            vals = struct.unpack(fmt, data[4:28])
        else:
            fmt = endian + "IIIII"
            vals = struct.unpack(fmt, data[4:24])
        self.cputype, self.cpusubtype = vals[0], vals[1]
        self.filetype, self.ncmds, self.sizeofcmds = vals[2], vals[3], vals[4]
        self.header_size = 28 if self.is_64 else 24
        self.flags = vals[5] if len(vals) > 5 else 0
        self.reserved = vals[6] if len(vals) > 6 else 0

    def _parse_load_commands(self):
        data = self.data
        self.load_commands = []
        off = self.header_size
        for i in range(self.ncmds):
            cmd, cmdsize = struct.unpack(self.endian + "II", data[off:off + 8])
            self.load_commands.append({
                "cmd": cmd, "cmdsize": cmdsize,
                "data": data[off:off + cmdsize]
            })
            off += cmdsize

    def _extract_sections(self):
        self.sections = {"text": None, "data": None, "cstring": None}
        for lc in self.load_commands:
            cmd = lc["cmd"]
            d = lc["data"]
            if cmd == 0x19:
                off = 32 if self.is_64 else 24
                nsects = struct.unpack(self.endian + "I", d[20:24])[0] if self.is_64 else struct.unpack(self.endian + "I", d[12:16])[0]
                for j in range(nsects):
                    if self.is_64:
                        sname = d[off:off + 16].rstrip(b"\x00").decode("latin-1", errors="replace")
                        soff = off + 72
                        soffset, salign, sreloff, snreloc, sflags, sres1, sres2, sres3 = \
                            struct.unpack(self.endian + "QQIIIIII", d[soff:soff + 40])
                        off += 80
                    else:
                        sname = d[off:off + 16].rstrip(b"\x00").decode("latin-1", errors="replace")
                        soff = off + 28
                        soffset, salign, sreloff, snreloc, sflags, sres1, sres2 = \
                            struct.unpack(self.endian + "IIIIIII", d[soff:soff + 28])
                        off += 48
                    sdata = self.data[soffset:soffset + 4096] if soffset else b""
                    if sname == "__text":
                        self.sections["text"] = sdata
                    elif sname == "__data":
                        self.sections["data"] = sdata
                    elif sname == "__cstring":
                        self.sections["cstring"] = sdata

    def _detect_cpu(self):
        self.cpu_name = {
            7: "x86", 7 | 0x01000000: "x86_64",
            12: "arm", 12 | 0x01000000: "arm64",
            18: "ppc", 18 | 0x01000000: "ppc64",
        }.get(self.cputype, f"cpu_0x{self.cputype:x}")
