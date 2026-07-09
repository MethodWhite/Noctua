import struct
from noctua.core.instruction import MWInstruction, MWFunction
from .base import BinaryLoader


class DEXLoader(BinaryLoader):
    name = "dex"

    @classmethod
    def check(cls, data):
        if data[:4] == b"dex\n":
            return True
        try:
            magic = struct.unpack("<I", data[:4])[0]
            return magic == 0x0a646578
        except struct.error:
            return False

    @classmethod
    def load(cls, data, engine):
        loader = cls()
        loader.data = data
        loader.engine = engine
        loader._parse_header()
        loader._parse_string_ids()
        loader._parse_type_ids()
        loader._parse_proto_ids()
        loader._parse_field_ids()
        loader._parse_method_ids()
        loader._parse_class_defs()
        loader.dex_parser = loader
        engine.loader = loader
        engine.dex = loader
        engine.sections = {}
        engine.strings = {}
        engine.functions = {}
        # Populate engine strings with clean ASCII only
        current = b''
        for i, byte in enumerate(data):
            if 32 <= byte < 127:
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    engine.strings[i - len(current)] = current.decode('ascii', errors='replace')
                current = b''
        if len(current) >= 4:
            engine.strings[len(data) - len(current)] = current.decode('ascii', errors='replace')
        # Class sections
        classes = getattr(loader, 'classes', []) or []
        for i, cls_def in enumerate(classes[:100]):
            cls_name = cls_def.get('name', f'class_{i}') if isinstance(cls_def, dict) else f'class_{i}'
            engine.sections[f'class_{cls_name}'] = {'addr': i, 'offset': i, 'size': 1, 'idx': i}
        # Method functions
        methods = getattr(loader, 'methods', []) or []
        for i, m in enumerate(methods[:5000]):
            mname = m.get('name', str(m)) if isinstance(m, dict) else str(m)
            engine.functions[i] = MWFunction(str(mname)[:80], i)
        print(f"  [DEX] classes={len(classes)} methods={len(methods)} strings={len(engine.strings)}")
        return loader

    def _parse_header(self):
        data = self.data
        self.header = {}
        self.header["magic"] = data[:8]
        self.header["checksum"] = struct.unpack("<I", data[8:12])[0]
        self.header["signature"] = data[12:32]
        self.header["file_size"] = struct.unpack("<I", data[32:36])[0]
        fields = "<IIIIIIIIIIIIIIIIIIII"
        vals = struct.unpack(fields, data[36:116])
        names = [
            "header_size", "endian_tag", "link_size", "link_off",
            "map_off", "string_ids_size", "string_ids_off",
            "type_ids_size", "type_ids_off", "proto_ids_size",
            "proto_ids_off", "field_ids_size", "field_ids_off",
            "method_ids_size", "method_ids_off", "class_defs_size",
            "class_defs_off", "data_size", "data_off"
        ]
        for n, v in zip(names, vals):
            self.header[n] = v

    def _parse_string_ids(self):
        data = self.data
        off = self.header["string_ids_off"]
        self.strings = []
        for i in range(self.header["string_ids_size"]):
            str_off = struct.unpack("<I", data[off:off + 4])[0]
            self.strings.append(self._read_uleb128_string(str_off))
            off += 4

    def _read_uleb128_string(self, off):
        data = self.data
        length = 0
        shift = 0
        pos = off
        while True:
            byte = data[pos]
            length |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
            if not (byte & 0x80):
                break
        raw = data[pos:pos + length]
        return raw.decode("utf-8", errors="replace")

    def _parse_type_ids(self):
        data = self.data
        off = self.header["type_ids_off"]
        self.types = []
        for i in range(self.header["type_ids_size"]):
            idx = struct.unpack("<I", data[off:off + 4])[0]
            self.types.append(self.strings[idx] if idx < len(self.strings) else f"type_{idx}")
            off += 4

    def _parse_proto_ids(self):
        data = self.data
        off = self.header["proto_ids_off"]
        self.protos = []
        for i in range(self.header["proto_ids_size"]):
            shorty_idx, return_type_idx, params_off = struct.unpack("<III", data[off:off + 12])
            self.protos.append({
                "shorty": self.strings[shorty_idx] if shorty_idx < len(self.strings) else "",
                "return_type": self.types[return_type_idx] if return_type_idx < len(self.types) else "",
                "params_off": params_off
            })
            off += 12

    def _parse_field_ids(self):
        data = self.data
        off = self.header["field_ids_off"]
        self.fields = []
        for i in range(self.header["field_ids_size"]):
            class_idx, type_idx, name_idx = struct.unpack("<HHI", data[off:off + 8])
            self.fields.append({
                "class": self.types[class_idx] if class_idx < len(self.types) else "",
                "type": self.types[type_idx] if type_idx < len(self.types) else "",
                "name": self.strings[name_idx] if name_idx < len(self.strings) else ""
            })
            off += 8

    def _parse_method_ids(self):
        data = self.data
        off = self.header["method_ids_off"]
        self.methods = []
        for i in range(self.header["method_ids_size"]):
            class_idx, proto_idx, name_idx = struct.unpack("<HHI", data[off:off + 8])
            self.methods.append({
                "class": self.types[class_idx] if class_idx < len(self.types) else "",
                "proto": self.protos[proto_idx] if proto_idx < len(self.protos) else {},
                "name": self.strings[name_idx] if name_idx < len(self.strings) else ""
            })
            off += 8

    def _parse_class_defs(self):
        data = self.data
        off = self.header["class_defs_off"]
        self.classes = []
        for i in range(self.header["class_defs_size"]):
            vals = struct.unpack("<IIIIIIII", data[off:off + 32])
            self.classes.append({
                "class_idx": vals[0], "access_flags": vals[1],
                "superclass_idx": vals[2], "interfaces_off": vals[3],
                "source_file_idx": vals[4], "annotations_off": vals[5],
                "class_data_off": vals[6], "static_values_off": vals[7]
            })
            off += 32


DEX_COND_BRANCHES = {
    0x32: "if_eq", 0x33: "if_ne", 0x34: "if_lt",
    0x35: "if_ge", 0x36: "if_gt", 0x37: "if_le",
    0x38: "if_eqz", 0x39: "if_nez", 0x3a: "if_ltz",
    0x3b: "if_gez", 0x3c: "if_gtz", 0x3d: "if_lez",
}

DEX_OTHER = {
    0x00: "nop", 0x01: "move", 0x02: "move_from16",
    0x03: "move_16", 0x04: "move_wide", 0x05: "move_wide_from16",
    0x06: "move_wide_16", 0x07: "move_object", 0x08: "move_object_from16",
    0x09: "move_object_16", 0x0a: "move_result", 0x0b: "move_result_wide",
    0x0c: "move_result_object", 0x0d: "move_exception",
    0x0e: "return_void", 0x10: "return", 0x11: "return_wide",
    0x12: "return_object", 0x14: "const_4", 0x15: "const_16",
    0x16: "const", 0x17: "const_high16", 0x18: "const_wide_16",
    0x19: "const_wide_32", 0x1a: "const_wide", 0x1b: "const_wide_high16",
    0x1c: "const_string", 0x1d: "const_string_jumbo",
    0x1e: "const_class", 0x22: "new_instance",
    0x23: "new_array", 0x24: "filled_new_array",
    0x25: "filled_new_array_range", 0x26: "fill_array_data",
    0x27: "throw", 0x28: "goto", 0x29: "goto_16", 0x2a: "goto_32",
    0x2b: "packed_switch", 0x2c: "sparse_switch",
    0x2d: "cmpl_float", 0x2e: "cmpg_float",
    0x2f: "cmpl_double", 0x30: "cmpg_double",
    0x31: "cmp_long", 0x3e: "aget", 0x44: "aget_object",
    0x4a: "aput", 0x50: "aput_object",
    0x52: "iget", 0x54: "iget_wide", 0x56: "iget_object",
    0x58: "iget_boolean", 0x5a: "iget_byte",
    0x5c: "iget_char", 0x5e: "iget_short",
    0x60: "iput", 0x62: "iput_wide", 0x64: "iput_object",
    0x66: "iput_boolean", 0x68: "iput_byte",
    0x6a: "iput_char", 0x6c: "iput_short",
    0x6e: "sget", 0x70: "sget_wide", 0x72: "sget_object",
    0x74: "sget_boolean", 0x76: "sget_byte",
    0x78: "sget_char", 0x7a: "sget_short",
    0x7c: "sput", 0x7e: "sput_wide", 0x80: "sput_object",
    0x82: "sput_boolean", 0x84: "sput_byte",
    0x86: "sput_char", 0x88: "sput_short",
    0x8a: "invoke_virtual", 0x8b: "invoke_super",
    0x8c: "invoke_direct", 0x8d: "invoke_static",
    0x8e: "invoke_interface", 0x90: "invoke_virtual_range",
    0x91: "invoke_super_range", 0x92: "invoke_direct_range",
    0x93: "invoke_static_range", 0x94: "invoke_interface_range",
    0x95: "neg_int", 0x96: "not_int", 0x97: "neg_long",
    0x98: "not_long", 0x99: "neg_float", 0x9a: "neg_double",
    0x9b: "int_to_long", 0x9c: "int_to_float", 0x9d: "int_to_double",
    0x9e: "long_to_int", 0x9f: "long_to_float", 0xa0: "long_to_double",
    0xa1: "float_to_int", 0xa2: "float_to_long", 0xa3: "float_to_double",
    0xa4: "double_to_int", 0xa5: "double_to_long", 0xa6: "double_to_float",
    0xa7: "int_to_byte", 0xa8: "int_to_char", 0xa9: "int_to_short",
    0xb0: "add_int", 0xb1: "sub_int", 0xb2: "mul_int",
    0xb3: "div_int", 0xb4: "rem_int", 0xb5: "and_int",
    0xb6: "or_int", 0xb7: "xor_int", 0xb8: "shl_int",
    0xb9: "shr_int", 0xba: "ushr_int", 0xbb: "add_long",
    0xbc: "sub_long", 0xbd: "mul_long", 0xbe: "div_long",
    0xbf: "rem_long", 0xc0: "and_long", 0xc1: "or_long",
    0xc2: "xor_long", 0xc3: "shl_long", 0xc4: "shr_long",
    0xc5: "ushr_long", 0xc6: "add_float", 0xc7: "sub_float",
    0xc8: "mul_float", 0xc9: "div_float", 0xca: "rem_float",
    0xcb: "add_double", 0xcc: "sub_double", 0xcd: "mul_double",
    0xce: "div_double", 0xcf: "rem_double",
    0xd0: "add_int_2addr", 0xd1: "sub_int_2addr",
    0xd2: "mul_int_2addr", 0xd3: "div_int_2addr",
    0xd4: "rem_int_2addr", 0xd5: "and_int_2addr",
    0xd6: "or_int_2addr", 0xd7: "xor_int_2addr",
    0xd8: "shl_int_2addr", 0xd9: "shr_int_2addr",
    0xda: "ushr_int_2addr", 0xdb: "add_long_2addr",
    0xdc: "sub_long_2addr", 0xdd: "mul_long_2addr",
    0xde: "div_long_2addr", 0xdf: "rem_long_2addr",
    0xe0: "and_long_2addr", 0xe1: "or_long_2addr",
    0xe2: "xor_long_2addr", 0xe3: "shl_long_2addr",
    0xe4: "shr_long_2addr", 0xe5: "ushr_long_2addr",
    0xe6: "add_float_2addr", 0xe7: "sub_float_2addr",
    0xe8: "mul_float_2addr", 0xe9: "div_float_2addr",
    0xea: "rem_float_2addr", 0xeb: "add_double_2addr",
    0xec: "sub_double_2addr", 0xed: "mul_double_2addr",
    0xee: "div_double_2addr", 0xef: "rem_double_2addr",
    0xf0: "add_int_lit16", 0xf1: "rsub_int",
    0xf2: "mul_int_lit16", 0xf3: "div_int_lit16",
    0xf4: "rem_int_lit16", 0xf5: "and_int_lit16",
    0xf6: "or_int_lit16", 0xf7: "xor_int_lit16",
    0xf8: "add_int_lit8", 0xf9: "rsub_int_lit8",
    0xfa: "mul_int_lit8", 0xfb: "div_int_lit8",
    0xfc: "rem_int_lit8", 0xfd: "and_int_lit8",
    0xfe: "or_int_lit8", 0xff: "xor_int_lit8",
}


class DEXDisassembler:
    @staticmethod
    def disassemble(code, offset=0):
        insns = []
        pos = 0
        while pos < len(code):
            opcode = code[pos]
            mnemonic = DEX_OTHER.get(opcode, DEX_COND_BRANCHES.get(opcode, f"unknown_0x{opcode:02x}"))
            op_val = code[pos + 1] if pos + 1 < len(code) else 0
            insns.append(MWInstruction(
                address=offset + pos,
                size=2,
                mnemonic=mnemonic,
                op_str=f"v{op_val}" if opcode != 0x00 else ""
            ))
            pos += 2
        return insns
