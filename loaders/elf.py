import struct
from capstone import *
from capstone.arm64 import *
from .base import BinaryLoader


class ELLoader(BinaryLoader):
    name = "elf"

    @classmethod
    def check(cls, data):
        return len(data) >= 4 and data[:4] == b'\x7fELF'

    @classmethod
    def load(cls, data, engine):
        engine.binary_type = 'elf'
        engine.sections = {}
        engine.strings = {}
        engine.functions = {}
        engine.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        engine.md.detail = True
        engine.entry = struct.unpack('<Q', data[0x18:0x20])[0]
        shoff = struct.unpack('<Q', data[0x28:0x30])[0]
        shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
        shstrndx = struct.unpack('<H', data[0x3e:0x40])[0]
        shstrtab_off = 0
        if shstrndx < shnum:
            sso = shoff + shstrndx * 64
            shstrtab_off = struct.unpack('<Q', data[sso+0x18:sso+0x20])[0]
        for i in range(shnum):
            so = shoff + i * 64
            name_idx = struct.unpack('<I', data[so:so+4])[0]
            sh_addr = struct.unpack('<Q', data[so+0x10:so+0x18])[0]
            sh_offset = struct.unpack('<Q', data[so+0x18:so+0x20])[0]
            sh_size = struct.unpack('<Q', data[so+0x20:so+0x28])[0]
            if shstrtab_off:
                raw = data[shstrtab_off + name_idx:].split(b'\x00')[0]
                try:
                    name = raw.decode('ascii')
                except:
                    name = f"section_{i}"
            else:
                name = f"section_{i}"
            engine.sections[name] = {'addr': sh_addr, 'offset': sh_offset, 'size': sh_size, 'idx': i}
        current = b''
        for i, b in enumerate(data):
            if 32 <= b < 127:
                current += bytes([b])
            else:
                if len(current) >= 4:
                    engine.strings[i - len(current)] = current.decode('ascii', errors='replace')
                current = b''
        patterns = [b'\xfd\x7b\xbf\xa9', b'\xfd\x7b\x01\xa9', b'\xe0\x03\x08\x2a']
        for pattern in patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos < 0 or pos > len(data) - 100:
                    break
                if pos >= 4:
                    pw = struct.unpack('<I', data[pos-4:pos])[0]
                    if pw == 0xd65f03c0 or (pw & 0xfc000000) == 0x14000000 or pos < 100:
                        if pos not in engine.functions:
                            from noctua.core.instruction import MWFunction
                            engine.functions[pos] = MWFunction(f"sub_{pos:x}", pos)
                else:
                    if pos not in engine.functions:
                        from noctua.core.instruction import MWFunction
                        engine.functions[pos] = MWFunction(f"sub_{pos:x}", pos)
                pos += 1
        if len(engine.functions) < 10:
            for word_off in range(0, len(data) - 4, 4):
                word = struct.unpack('<I', data[word_off:word_off+4])[0]
                if (word & 0xfc000000) == 0x94000000:
                    offset = word & 0x03ffffff
                    if offset & 0x02000000:
                        offset |= 0xfc000000
                    target = word_off + offset * 4
                    if 0 < target < len(data) and target not in engine.functions:
                        from noctua.core.instruction import MWFunction
                        engine.functions[target] = MWFunction(f"call_target_{target:x}", target)
        print(f"  [ELF] sections={len(engine.sections)} strings={len(engine.strings)} functions={len(engine.functions)}")
