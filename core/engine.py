import struct, os
from capstone import *
from capstone.arm64 import *
from .instruction import MWInstruction, MWFunction
from .signal import SignalTools


class MWREEngine:
    MAGIC_MAP = [
        (b"\x7fELF", "elf"),
        (b"MZ", "pe"),
        (b"\xfe\xed\xfa\xce", "macho"),
        (b"\xce\xfa\xed\xfe", "macho"),
        (b"\xfe\xed\xfa\xcf", "macho"),
        (b"\xcf\xfa\xed\xfe", "macho"),
        (b"dex\n", "dex"),
        (b"\x00asm", "wasm"),
        (b"RIFF", "webp"),
    ]

    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.functions = {}
        self.sections = {}
        self.strings = {}
        self.dex_parser = None
        self.riff_chunks = {}
        self.binary_type = 'unknown'
        self.entry = 0
        self._detect_and_load()

    def _detect_and_load(self):
        for magic, name in self.MAGIC_MAP:
            if self.data[:len(magic)] == magic and magic != b'MZ':
                self.binary_type = name
                break
        if self.binary_type == 'unknown':
            if self.data[:2] == b'MZ' and len(self.data) > 0x40:
                pe_off = struct.unpack('<I', self.data[0x3c:0x40])[0]
                if pe_off + 4 <= len(self.data) and self.data[pe_off:pe_off+4] == b'PE\x00\x00':
                    self.binary_type = 'pe'
            if self.binary_type == 'unknown':
                self.binary_type = 'generic'
        self._load()

    def _load(self):
        import importlib
        loader_map = {
            'elf': 'ELLoader', 'dex': 'DEXLoader', 'pe': 'PELoader',
            'macho': 'MachOLoader', 'wasm': 'WASMLoader', 'webp': 'WebPLoader',
            'generic': 'GenericLoader',
        }
        cls_name = loader_map.get(self.binary_type, 'GenericLoader')
        try:
            mod = importlib.import_module(f'noctua.loaders.{self.binary_type}')
            if hasattr(mod, cls_name):
                getattr(mod, cls_name).load(self.data, self)
            if self.binary_type == 'dex':
                self.dex_parser = getattr(self, 'dex', None) or getattr(self, 'loader', None)
        except Exception:
            if self.binary_type not in ('generic',):
                from noctua.loaders.generic import GenericLoader
                GenericLoader.load(self.data, self)
            self.extract_strings()

    def extract_strings(self, min_length=4):
        if isinstance(self.strings, dict):
            current = b""
            for i, byte in enumerate(self.data):
                if 32 <= byte <= 126:
                    current += bytes([byte])
                else:
                    if len(current) >= min_length:
                        try:
                            self.strings[i - len(current)] = current.decode("ascii")
                        except Exception:
                            pass
                    current = b""
            if len(current) >= min_length:
                try:
                    self.strings[len(self.data) - len(current)] = current.decode("ascii")
                except Exception:
                    pass

    def extract_strings_list(self, min_length=4):
        result = []
        current = b""
        for byte in self.data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    try:
                        result.append(current.decode("ascii"))
                    except Exception:
                        pass
                current = b""
        if len(current) >= min_length:
            try:
                result.append(current.decode("ascii"))
            except Exception:
                pass
        return result

    def disassemble_function(self, func, max_insns=500):
        offset = func.entry if isinstance(func.entry, int) else func.entry
        if offset >= len(self.data) - 4:
            return func
        code = self.data[offset:offset + max_insns * 4]
        count = 0
        for insn in self.md.disasm(code, offset):
            if count >= max_insns:
                break
            mw_i = MWInstruction(insn.address, code[insn.address-offset:insn.address-offset+4],
                                 insn.mnemonic, insn.op_str, insn)
            func.instructions.append(mw_i)
            if 'bl' in insn.mnemonic and insn.op_str:
                try:
                    t = int(insn.op_str.replace('#', '').strip(), 16) if insn.op_str.strip().startswith('0x') else int(insn.op_str.strip())
                    func.calls.append((insn.address, t))
                except: pass
            if insn.mnemonic == 'ret':
                break
            count += 1
        return func

    def find_functions_by_prologue(self):
        patterns = [b'\xfd\x7b\xbf\xa9', b'\xfd\x7b\x01\xa9', b'\xe0\x03\x08\x2a']
        funcs = {}
        for pattern in patterns:
            pos = 0
            while True:
                pos = self.data.find(pattern, pos)
                if pos < 0 or pos > len(self.data) - 100:
                    break
                if pos >= 4:
                    pw = struct.unpack('<I', self.data[pos-4:pos])[0]
                    if pw == 0xd65f03c0 or (pw & 0xfc000000) == 0x14000000 or pos < 100:
                        if pos not in funcs:
                            funcs[pos] = MWFunction(f"sub_{pos:x}", pos)
                else:
                    if pos not in funcs:
                        funcs[pos] = MWFunction(f"sub_{pos:x}", pos)
                pos += 1
        if len(funcs) < 10:
            for word_off in range(0, len(self.data) - 4, 4):
                word = struct.unpack('<I', self.data[word_off:word_off+4])[0]
                if (word & 0xfc000000) == 0x94000000:
                    offset = word & 0x03ffffff
                    if offset & 0x02000000:
                        offset |= 0xfc000000
                    target = word_off + offset * 4
                    if 0 < target < len(self.data) and target not in funcs:
                        funcs[target] = MWFunction(f"call_target_{target:x}", target)
        self.functions = funcs
        return funcs

    def run(self):
        print(f"\n[+] Analysis complete")
        return {
            "binary_type": self.binary_type,
            "sections": len(self.sections),
            "functions": len(self.functions),
            "strings": len(self.strings),
        }
