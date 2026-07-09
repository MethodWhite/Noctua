import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from .base import BinaryLoader


class PELoader(BinaryLoader):
    name = "pe"

    @classmethod
    def check(cls, data):
        if data[:2] != b"MZ":
            return False
        pe_offset = struct.unpack("<I", data[60:64])[0]
        return data[pe_offset:pe_offset + 4] == b"PE\x00\x00"

    @classmethod
    def load(cls, data, engine):
        loader = cls()
        loader.data = data
        loader.engine = engine
        loader._parse_dos_header()
        loader._parse_pe_header()
        loader._parse_section_table()
        loader._extract_strings()
        loader._detect_machine()
        engine.loader = loader
        engine.pe = loader
        return loader

    def _parse_dos_header(self):
        data = self.data
        self.dos_header = {
            "e_magic": data[:2],
            "e_lfanew": struct.unpack("<I", data[60:64])[0]
        }

    def _parse_pe_header(self):
        data = self.data
        off = self.dos_header["e_lfanew"]
        pe_sig = data[off:off + 4]
        coff = data[off + 4:off + 24]
        self.coff_header = {
            "machine": struct.unpack("<H", coff[:2])[0],
            "number_of_sections": struct.unpack("<H", coff[2:4])[0],
            "time_date_stamp": struct.unpack("<I", coff[4:8])[0],
            "pointer_to_symbol_table": struct.unpack("<I", coff[8:12])[0],
            "number_of_symbols": struct.unpack("<I", coff[12:16])[0],
            "size_of_optional_header": struct.unpack("<H", coff[16:18])[0],
            "characteristics": struct.unpack("<H", coff[18:20])[0],
        }
        opt_off = off + 24
        opt_size = self.coff_header["size_of_optional_header"]
        opt_data = data[opt_off:opt_off + opt_size]
        if len(opt_data) >= 2:
            self.magic = struct.unpack("<H", opt_data[:2])[0]
        self.optional_header = opt_data
        self.pe_offset = off

    def _parse_section_table(self):
        data = self.data
        opt_size = self.coff_header["size_of_optional_header"]
        sec_off = self.pe_offset + 24 + opt_size
        self.sections = []
        for i in range(self.coff_header["number_of_sections"]):
            raw = data[sec_off:sec_off + 40]
            name_raw = raw[:8]
            name = name_raw.rstrip(b"\x00").decode("latin-1", errors="replace")
            vals = struct.unpack("<IIIIIIII", raw[8:40])
            sec = {
                "name": name,
                "virtual_size": vals[0],
                "virtual_address": vals[1],
                "size_of_raw_data": vals[2],
                "pointer_to_raw_data": vals[3],
                "pointer_to_relocations": vals[4],
                "pointer_to_linenumbers": vals[5],
                "number_of_relocations": vals[6],
                "number_of_linenumbers": vals[7],
            }
            sec["data"] = data[sec["pointer_to_raw_data"]:sec["pointer_to_raw_data"] + sec["size_of_raw_data"]]
            self.sections.append(sec)
            sec_off += 40

    def _extract_strings(self):
        self.strings = set()
        for sec in self.sections:
            if sec["size_of_raw_data"] > 64:
                self._find_strings_in(sec["data"])

    def _find_strings_in(self, blob):
        current = []
        for byte in blob:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    self.strings.add("".join(current))
                current = []

    def _detect_machine(self):
        machine = self.coff_header.get("machine", 0)
        engine = self.engine
        if machine == 0x8664:
            engine.md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif machine in (0x14c, 0x1d3):
            engine.md = Cs(CS_ARCH_X86, CS_MODE_32)
