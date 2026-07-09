import struct
from .base import BinaryLoader


class WebPParser:
    def __init__(self, data):
        self.data = data
        self.chunks = []

    def parse(self):
        data = self.data
        pos = 0
        while pos + 8 <= len(data):
            chunk_id = data[pos:pos + 4]
            chunk_size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
            chunk_size = (chunk_size + 1) & ~1
            chunk_data = data[pos + 8:pos + 8 + chunk_size] if chunk_size else b""
            self.chunks.append({
                "id": chunk_id.decode("latin-1", errors="replace"),
                "size": chunk_size,
                "data": chunk_data,
            })
            pos += 8 + chunk_size


class TIFFParser:
    def __init__(self, data):
        self.data = data
        self.entries = []

    def parse(self):
        data = self.data
        if len(data) < 8:
            return
        endian = data[:2]
        if endian == b"II":
            endian_char = "<"
        elif endian == b"MM":
            endian_char = ">"
        else:
            return
        tiff_magic = struct.unpack(endian_char + "H", data[2:4])[0]
        if tiff_magic != 42:
            return
        ifd_offset = struct.unpack(endian_char + "I", data[4:8])[0]
        self._parse_ifd(data, ifd_offset, endian_char)

    def _parse_ifd(self, data, offset, endian):
        if offset + 2 > len(data):
            return
        num_entries = struct.unpack(endian + "H", data[offset:offset + 2])[0]
        pos = offset + 2
        for i in range(num_entries):
            if pos + 12 > len(data):
                break
            tag = struct.unpack(endian + "H", data[pos:pos + 2])[0]
            typ = struct.unpack(endian + "H", data[pos + 2:pos + 4])[0]
            count = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
            value_offset = struct.unpack(endian + "I", data[pos + 8:pos + 12])[0]
            self.entries.append({
                "tag": tag, "type": typ,
                "count": count, "value_offset": value_offset
            })
            if tag == 0x5741:
                self.wa_tag = self.entries[-1]
            pos += 12


class WebPLoader(BinaryLoader):
    name = "webp"

    @classmethod
    def check(cls, data):
        return data[:4] == b"RIFF" and data[8:12] == b"WEBP"

    @classmethod
    def load(cls, data, engine):
        loader = cls()
        loader.data = data
        loader.engine = engine
        loader._parse_riff()
        loader._parse_vp8x()
        loader._parse_exif()
        engine.loader = loader
        engine.webp = loader
        return loader

    def _parse_riff(self):
        parser = WebPParser(self.data[12:])
        parser.parse()
        self.riff_chunks = parser.chunks

    def _parse_vp8x(self):
        for chunk in self.riff_chunks:
            if chunk["id"] == "VP8X":
                if len(chunk["data"]) >= 4:
                    flags = struct.unpack("<I", chunk["data"][:4])[0]
                    self.vp8x_flags = {
                        "icc": bool(flags & 0x20),
                        "alpha": bool(flags & 0x10),
                        "exif": bool(flags & 0x08),
                        "xmp": bool(flags & 0x04),
                        "animation": bool(flags & 0x02),
                    }
                break

    def _parse_exif(self):
        for chunk in self.riff_chunks:
            if chunk["id"] == "EXIF":
                parser = TIFFParser(chunk["data"])
                parser.parse()
                self.exif_entries = parser.entries
                break
