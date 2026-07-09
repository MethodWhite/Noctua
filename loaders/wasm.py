import struct
from .base import BinaryLoader


class WASMLoader(BinaryLoader):
    name = "wasm"

    @classmethod
    def check(cls, data):
        return data[:4] == b"\x00asm"

    @classmethod
    def load(cls, data, engine):
        loader = cls()
        loader.data = data
        loader.engine = engine
        loader._parse_header()
        loader._parse_sections()
        loader._extract_strings()
        engine.loader = loader
        engine.wasm = loader
        return loader

    def _parse_header(self):
        self.magic = self.data[:4]
        self.version = struct.unpack("<I", self.data[4:8])[0]

    def _parse_sections(self):
        self.sections = []
        pos = 8
        while pos < len(self.data):
            section_id = self.data[pos]
            pos += 1
            length, pos = self._read_uleb128(pos)
            section_data = self.data[pos:pos + length]
            self.sections.append({
                "id": section_id,
                "name": self._section_name(section_id),
                "length": length,
                "data": section_data,
            })
            if section_id == 0:
                self._parse_custom_section(self.sections[-1])
            pos += length

    def _read_uleb128(self, pos):
        result = 0
        shift = 0
        while True:
            byte = self.data[pos]
            result |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
            if not (byte & 0x80):
                break
        return result, pos

    def _section_name(self, sid):
        names = {
            0: "custom", 1: "type", 2: "import", 3: "function",
            4: "table", 5: "memory", 6: "global", 7: "export",
            8: "start", 9: "element", 10: "code", 11: "data",
            12: "datacount"
        }
        return names.get(sid, f"unknown_{sid}")

    def _parse_custom_section(self, section):
        data = section["data"]
        pos = 0
        name_len, pos = self._read_uleb128(pos) if pos < len(data) else (0, pos)
        section["custom_name"] = data[pos:pos + name_len].decode("utf-8", errors="replace")
        section["custom_data"] = data[pos + name_len:]

    def _extract_strings(self):
        self.strings = set()
        for sec in self.sections:
            if sec["id"] == 0 and sec.get("custom_name") == "name":
                self._parse_name_section(sec)
            self._find_printable(sec["data"])

    def _parse_name_section(self, section):
        data = section.get("custom_data", b"")
        pos = 0
        while pos < len(data):
            name_len, pos = self._read_uleb128(pos) if pos < len(data) else (0, pos)
            if pos + name_len <= len(data):
                name = data[pos:pos + name_len].decode("utf-8", errors="replace")
                self.strings.add(name)
                pos += name_len

    def _find_printable(self, blob):
        current = []
        for byte in blob:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    self.strings.add("".join(current))
                current = []
