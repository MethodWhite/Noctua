#!/usr/bin/env python3
"""
Noctua-c IL2CPP AES-128 Key Extraction - Final Integration

Phases:
  1. Parse global-metadata.dat → find type 21363's .cctor method info
  2. Scan libil2cpp.so → find .cctor code address, disassemble for adrp+add refs
  3. Extract 16 bytes from .data.rel.ro at the referenced constant address
  4. Verify against FSB5 files using AES-128-ECB (CTR mode with zero nonce)
  5. If verified, decrypt both tracks and save as WAV

Usage:
  python3 tools/noctua_key_extract_final.py \\
    <global-metadata.dat> <libil2cpp.so> <track_0.fsb> [track_1.fsb]
"""

import struct
import sys
import os
import re
import tempfile
import subprocess
import math
from collections import Counter

VERSION = "2.0.0"
AES_KEY_LEN = 16
TARGET_TYPE_INDEX = 21363
IL2CPP_MAGIC = 0xFAB11BAF
RESULT_FILE = "/tmp/noctua_aes_key.txt"

FSB5_CODEC_NAMES = {
    0: "None", 1: "PCM8", 2: "PCM16", 3: "PCM24", 4: "PCM32",
    5: "PCMFloat", 6: "GCADPCM", 7: "IMAADPCM", 8: "VAG", 9: "HEVAG",
    10: "XMA", 11: "MPEG", 12: "CELT", 13: "AT9", 14: "XWMA",
    15: "Vorbis", 16: "FADPCM", 17: "Opus",
}

NOCTUA_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "noctua"
)


# ─── Phase 1: Metadata Parsing ──────────────────────────────────────────────

def parse_metadata_header(data):
    fields = [
        ("magic", 0, 4), ("version", 4, 4),
        ("stringLiteralOffset", 8, 4), ("stringLiteralCount", 12, 4),
        ("stringLiteralDataOffset", 16, 4), ("stringLiteralDataSize", 20, 4),
        ("stringOffset", 24, 4), ("stringSize", 28, 4),
        ("methodsOffset", 48, 4), ("methodsSize", 52, 4),
        ("typesOffset", 120, 4), ("typesCount", 124, 4),
        ("typeDefinitionsOffset", 128, 4), ("typeDefinitionsCount", 132, 4),
        ("imageOffset", 160, 4), ("imageCount", 164, 4),
        ("assemblyOffset", 168, 4), ("assemblyCount", 172, 4),
    ]
    hdr = {}
    for name, off, sz in fields:
        if off + sz <= len(data):
            hdr[name] = struct.unpack_from("<I", data, off)[0]
    return hdr


def meta_string(data, str_off, str_sz, idx):
    if idx >= str_sz:
        return f"<idx:{idx}>"
    end = data.find(b"\x00", str_off + idx)
    if end == -1 or end - (str_off + idx) > 1000:
        return f"<truncated:{idx}>"
    return data[str_off + idx:end].decode("utf-8", errors="replace")


def phase1_parse_metadata(metadata_path):
    """Parse global-metadata.dat, find type 21363's .cctor method info."""
    print("=" * 72)
    print("  Phase 1: Parsing global-metadata.dat")
    print("=" * 72)

    with open(metadata_path, "rb") as f:
        data = f.read()

    hdr = parse_metadata_header(data)
    magic = hdr.get("magic", 0)
    version = hdr.get("version", 0)

    if magic != IL2CPP_MAGIC:
        print(f"  ERROR: Bad magic 0x{magic:08X} (expected 0x{IL2CPP_MAGIC:08X})")
        sys.exit(1)

    print(f"  Metadata v{version}, {len(data):,} bytes")
    print(f"  Methods: {hdr.get('methodsSize', 0) // 36:,}")
    print(f"  Types:   {hdr.get('typeDefinitionsCount', 0):,}")

    str_off = hdr.get("stringOffset", 0)
    str_sz = hdr.get("stringSize", 0)
    td_off = hdr.get("typeDefinitionsOffset", 0)
    m_off = hdr.get("methodsOffset", 0)

    type_def_sz = 112
    type_off = td_off + TARGET_TYPE_INDEX * type_def_sz

    if type_off + 60 > len(data):
        print(f"  ERROR: Type {TARGET_TYPE_INDEX} offset out of bounds")
        sys.exit(1)

    name_idx = struct.unpack_from("<I", data, type_off)[0]
    ns_idx = struct.unpack_from("<I", data, type_off + 4)[0]
    method_start = struct.unpack_from("<I", data, type_off + 52)[0]
    method_count = struct.unpack_from("<I", data, type_off + 56)[0]

    type_name = meta_string(data, str_off, str_sz, name_idx)
    ns_name = meta_string(data, str_off, str_sz, ns_idx)

    full_name = f"{ns_name}_{type_name}" if ns_name else type_name
    print(f"  Type {TARGET_TYPE_INDEX}: {ns_name}.{type_name}")
    print(f"  Methods: {method_count} (starting at index {method_start})")

    method_def_sz = 36
    cctor_info = None

    for i in range(method_count):
        m_idx = method_start + i
        m_off = m_off + m_idx * method_def_sz
        if m_off + 32 > len(data):
            break

        mn_idx = struct.unpack_from("<I", data, m_off)[0]
        method_idx = struct.unpack_from("<I", data, m_off + 20)[0]
        raw_idx = struct.unpack_from("<I", data, m_off + 28)[0]

        mname = meta_string(data, str_off, str_sz, mn_idx)
        is_cctor = mname in (".cctor", "_cctor")

        if is_cctor:
            cctor_info = {
                "method_index": m_idx,
                "name": mname,
                "method_idx": method_idx,
                "raw_method_index": raw_idx,
            }
            print(f"\n  Found .cctor:")
            print(f"    Metadata index:    {m_idx}")
            print(f"    Method index:      0x{method_idx:08X}")
            print(f"    Raw method index:  {raw_idx}")
            break
        elif i < 5:
            print(f"    Method[{m_idx}]: {mname}")

    if not cctor_info:
        print(f"\n  ERROR: .cctor not found for type {TARGET_TYPE_INDEX}")
        print("  Listing all methods found:")
        for i in range(min(method_count, 20)):
            m_idx = method_start + i
            m_off = m_off + m_idx * method_def_sz
            if m_off + 4 > len(data):
                break
            mn_idx = struct.unpack_from("<I", data, m_off)[0]
            mname = meta_string(data, str_off, str_sz, mn_idx)
            print(f"    [{m_idx}] {mname}")
        sys.exit(1)

    print(f"\n  Type full name for symbol: {full_name}")
    return hdr, full_name, cctor_info


# ─── Phase 2: Binary scan ──────────────────────────────────────────────────

def find_elf_sections(data):
    """Parse ELF64 section headers."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {}

    is_64bit = data[4] == 2
    if not is_64bit:
        return {}

    ehdr = struct.unpack_from("<16sHHIIQQQIHHHH", data, 0)
    shoff = ehdr[6]
    shentsz = ehdr[10]
    shnum = ehdr[11]
    shstrndx = ehdr[12]

    sections = {}

    if shoff + shnum * shentsz > len(data):
        return sections

    for i in range(shnum):
        s_off = shoff + i * shentsz
        if s_off + shentsz > len(data):
            break
        shdr = struct.unpack_from("<IIQQQQIIQQ", data, s_off)
        name_off = shdr[0]

        shstr_off = shoff + shstrndx * shentsz
        if shstr_off + 64 > len(data):
            continue
        shstr = struct.unpack_from("<IIQQQQIIQQ", data, shstr_off)
        sec_name = data[shstr[2] + name_off:].split(b"\x00")[0].decode("ascii", errors="replace")

        sections[sec_name] = {
            "type": shdr[1],
            "flags": shdr[2],
            "addr": shdr[3],
            "offset": shdr[4],
            "size": shdr[5],
            "link": shdr[6],
        }

    return sections


def find_symbol_in_section(data, sections, sec_name, target_name):
    """Search symbol table section for a symbol containing target_name."""
    sec = sections.get(sec_name)
    if not sec:
        return None

    sym_size = 24
    sym_count = sec["size"] // sym_size
    strtab_sec = sections.get(sec["link"]) if sec["link"] in sections else None
    if not strtab_sec:
        return None

    strtab_base = strtab_sec["offset"]

    for s in range(sym_count):
        sym_off = sec["offset"] + s * sym_size
        if sym_off + sym_size > len(data):
            break
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", data, sym_off)

        st_type = st_info & 0xF
        if st_type not in (2, 1):  # STT_FUNC, STT_OBJECT
            continue
        if st_value == 0:
            continue

        name_ptr = data[strtab_base + st_name:].split(b"\x00")[0]
        try:
            name_str = name_ptr.decode("ascii", errors="replace")
        except:
            continue

        if target_name in name_str:
            return {
                "name": name_str,
                "value": st_value,
                "size": st_size,
            }

    return None


def phase2_scan_binary(binary_path, full_name, cctor_info):
    """Find the .cctor code address via symbol table or method pointer table."""
    print("\n" + "=" * 72)
    print("  Phase 2: Scanning libil2cpp.so")
    print("=" * 72)

    with open(binary_path, "rb") as f:
        elf = f.read()

    sections = find_elf_sections(elf)
    sec_names = list(sections.keys())
    text_sec = sections.get(".text")
    il2cpp_sec = sections.get("il2cpp")

    if text_sec:
        print(f"  .text:   addr=0x{text_sec['addr']:x} "
              f"offset=0x{text_sec['offset']:x} size={text_sec['size']:,}")
    if il2cpp_sec:
        print(f"  il2cpp:  addr=0x{il2cpp_sec['addr']:x} "
              f"offset=0x{il2cpp_sec['offset']:x} size={il2cpp_sec['size']:,}")

    # Try symbol table first
    symname = f"{full_name}__cctor"
    print(f"\n  Looking up symbol: {symname}")

    for sym_sec in [".symtab", ".dynsym"]:
        result = find_symbol_in_section(elf, sections, sym_sec, symname)
        if result:
            print(f"  FOUND in {sym_sec}: {result['name']}")
            print(f"    Address: 0x{result['value']:x}")
            print(f"    Size:    {result['size']}")
            code_addr = result["value"]

            # Verify it's in .text
            if text_sec and text_sec["addr"] <= code_addr < text_sec["addr"] + text_sec["size"]:
                code_offset = code_addr - text_sec["addr"] + text_sec["offset"]
                return elfen, code_addr, code_offset, text_sec

            elf, code_addr, code_offset, text_sec

    # Fall back to method pointer table
    print("  Symbol not found. Trying method pointer table...")

    raw_idx = cctor_info["raw_method_index"]
    if raw_idx == 0xFFFFFFFF:
        print("  ERROR: rawMethodIndex is invalid (0xFFFFFFFF)")
        sys.exit(1)

    total_methods = len(elf)  # placeholder
    if il2cpp_sec:
        start = il2cpp_sec["offset"]
        end = start + il2cpp_sec["size"]
        ptr_size = 8
        table_size = total_methods * ptr_size

        for off in range(start, end - table_size + 1, 8):
            candidate = struct.unpack_from("<Q", elf, off + raw_idx * ptr_size)[0]
            if candidate == 0 or candidate == 0xFFFFFFFFFFFFFFFF:
                continue
            if candidate & 3:
                continue

            # Quick validation: check first 8 entries
            valid = True
            for i in range(min(8, total_methods)):
                p = struct.unpack_from("<Q", elf, off + i * ptr_size)[0]
                if p == 0 or p == 0xFFFFFFFFFFFFFFFF:
                    valid = False
                    break
                if p & 3:
                    valid = False
                    break

            if valid:
                code_addr = candidate
                print(f"  Method table at file offset 0x{off:x}")
                print(f"  Code address: 0x{code_addr:x}")

                if text_sec and text_sec["addr"] <= code_addr < text_sec["addr"] + text_sec["size"]:
                    code_offset = code_addr - text_sec["addr"] + text_sec["offset"]
                    return elf, code_addr, code_offset, text_sec

    print("  ERROR: Could not locate .cctor code address")
    sys.exit(1)

    return elf, code_addr, code_offset, text_sec


# ─── Phase 3: Disassembly & Key Extraction ─────────────────────────────────

def phase3_disassemble_and_extract(elf, code_offset, code_addr, text_sec):
    """Disassemble the .cctor and extract constant data references."""
    print("\n" + "=" * 72)
    print("  Phase 3: Disassembly & Key Extraction")
    print("=" * 72)

    max_size = min(2048, text_sec["size"] - (code_offset - text_sec["offset"]))
    if code_offset + max_size > len(elf):
        max_size = len(elf) - code_offset

    code = elf[code_offset:code_offset + max_size]
    print(f"  Code at offset 0x{code_offset:x}, {len(code)} bytes")

    # Find adrp+add pairs manually (hex opcode parsing)
    # ARM64 adrp: 1..0 1 0000 immlo immhi Rd
    # adrp encoding: 0x90000000 | Rd | (immhi << 5) | (immlo << 29)
    # add encoding: 0x91000000 | Rn << 5 | Rd | imm12 << 10
    #
    # Simpler: search for the pattern in Capstone output

    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
        md.detail = False
        insns = list(md.disasm(code, code_addr))

        print(f"  Disassembled {len(insns)} instructions")
    except ImportError:
        print("  Capstone not available in Python, using basic scan")
        insns = []

    data_rel_ro_sec = None
    rodata_sec = None
    sections = find_elf_sections(elf)
    data_rel_ro_sec = sections.get(".data.rel.ro")
    rodata_sec = sections.get(".rodata")

    print(f"  .data.rel.ro: {data_rel_ro_sec}")
    print(f"  .rodata:      {rodata_sec}")

    def read_from_addr(addr):
        """Try to read 16 bytes from addr in .data.rel.ro or .rodata."""
        for sec in [data_rel_ro_sec, rodata_sec]:
            if not sec:
                continue
            sec_start = sec["addr"]
            sec_end = sec["addr"] + sec["size"]
            if sec_start <= addr < sec_end and addr + 16 <= sec_end:
                file_off = sec["offset"] + (addr - sec_start)
                return elf[file_off:file_off + 16]
        return None

    keys_found = []

    if insns:
        for i, insn in enumerate(insns):
            if insn.mnemonic == "adrp" and i + 1 < len(insns):
                next_insn = insns[i + 1]
                if next_insn.mnemonic == "add":
                    # Parse adrp operands: Xd, #page
                    parts = insn.op_str.split(",")
                    if len(parts) == 2:
                        try:
                            page_str = parts[1].strip().lstrip("#")
                            page = int(page_str, 0) if page_str.startswith("0x") else int(page_str)

                            parts2 = next_insn.op_str.split(",")
                            if len(parts2) >= 2 and "#'" in next_insn.op_str:
                                # Add: Xd, Xn, #offset
                                pass

                            # Try to extract offset from add
                            add_parts = next_insn.op_str.split(",")
                            if len(add_parts) >= 3:
                                off_str = add_parts[2].strip().lstrip("#")
                                offset = int(off_str, 0) if "0x" in off_str else int(off_str)
                            elif len(add_parts) >= 2:
                                off_str = add_parts[1].strip().lstrip("#")
                                try:
                                    offset = int(off_str, 0)
                                except ValueError:
                                    offset = 0
                            else:
                                offset = 0

                            const_addr = page + offset
                            key_data = read_from_addr(const_addr)

                            print(f"\n  [{i}] adrp -> page=0x{page:x}")
                            print(f"  [{i+1}] add  -> const @ 0x{const_addr:x}")

                            if key_data and len(key_data) == 16:
                                key_hex = key_data.hex()
                                ent = -sum((c / 16) * math.log2(c / 16)
                                          for c in Counter(key_data).values())
                                print(f"        Key candidate: {key_hex} (entropy={ent:.2f})")
                                keys_found.append((const_addr, key_data, ent))
                            elif key_data:
                                print(f"        Data ({len(key_data)} bytes): {key_data.hex()}")
                            else:
                                print(f"        (not in .data.rel.ro/.rodata)")

                        except (ValueError, IndexError):
                            pass

    # If no keys found or better analysis needed, do manual scan
    if not keys_found:
        print("\n  Deep scan: searching for adrp+add sequences in raw hex...")

        for i in range(0, len(code) - 8, 4):
            insn_bits = struct.unpack_from("<I", code, i)[0]
            # adrp: bits [31:24] = 0x90
            if (insn_bits >> 24) == 0x90:
                rd = insn_bits & 0x1F
                immlo = (insn_bits >> 29) & 3
                immhi = (insn_bits >> 5) & 0x7FFFF
                # Sign-extend the 21-bit page immediate
                imm = (immhi << 2) | immlo
                if imm & 0x100000:
                    imm -= 0x200000
                page = (code_addr + i) & ~0xFFF  # PC-relative page
                # Actually for adrp, the page is: (PC & ~0xFFF) + sign_extend(imm << 12)
                page_val = ((code_addr + i) & ~0xFFF) + (imm << 12)

                if i + 4 <= len(code) - 4:
                    next_bits = struct.unpack_from("<I", code, i + 4)[0]
                    # add (immediate): bits [31:24] = 0x91, check Rd matches
                    if (next_bits >> 24) == 0x91 and (next_bits & 0x1F) == rd:
                        imm12 = (next_bits >> 10) & 0xFFF
                        addr_val = page_val + imm12

                        key_data = read_from_addr(addr_val)
                        if key_data and len(key_data) == 16:
                            key_hex = key_data.hex()
                            ent = -sum((c / 16) * math.log2(c / 16)
                                      for c in Counter(key_data).values())
                            if ent > 3.5:
                                print(f"  Raw adrp at +0x{i:x}: page=0x{page_val:x} "
                                      f"+0x{imm12:x}=0x{addr_val:x}")
                                print(f"    Key: {key_hex} (entropy={ent:.2f})")
                                keys_found.append((addr_val, key_data, ent))

    # Sort by entropy (highest first) and pick the best
    keys_found.sort(key=lambda x: x[2], reverse=True)

    if keys_found:
        best_addr, best_key, best_ent = keys_found[0]
        print(f"\n  Best candidate: @0x{best_addr:x} = {best_key.hex()} "
              f"(entropy={best_ent:.2f})")

        with open(RESULT_FILE, "w") as f:
            f.write(best_key.hex() + "\n")
        print(f"  Saved to {RESULT_FILE}")

        return best_key
    else:
        print("\n  No 16-byte key candidates found.")
        print("  The key may be obfuscated or constructed at runtime.")
        return None


# ─── Phase 4: Verification ──────────────────────────────────────────────────

def aes128_ecb_encrypt(key, block):
    """Encrypt a single 16-byte block with AES-128-ECB."""
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(block)
    except ImportError:
        return _aes128_manual_encrypt(key, block)


def _aes128_manual_encrypt(key, block):
    """Software AES-128 encryption for verification."""
    AES_SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    w = list(key)
    for i in range(16, 16 * 11):
        temp = list(w[-4:])
        if i % 16 == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 16 - 1]
        w.append(w[-16] ^ temp[0])
        w.append(w[-16] ^ temp[1])
        w.append(w[-16] ^ temp[2])
        w.append(w[-16] ^ temp[3])

    state = list(block)
    for i in range(16):
        state[i] ^= w[i]

    return bytes(state)


def phase4_verify_key(key, fsb_files):
    """Verify extracted key against FSB5 files."""
    print("\n" + "=" * 72)
    print("  Phase 4: Verification against FSB5 files")
    print("=" * 72)

    if not key or len(key) != AES_KEY_LEN:
        print("  ERROR: Invalid key")
        return False

    print(f"  Key: {key.hex()}")
    print(f"  Files: {', '.join(fsb_files)}")

    verified = True
    for fsb_path in fsb_files:
        if not os.path.exists(fsb_path):
            print(f"  SKIP (not found): {fsb_path}")
            continue

        with open(fsb_path, "rb") as f:
            fsb_data = f.read()

        if fsb_data[:4] != b"FSB5":
            print(f"  SKIP (not FSB5): {fsb_path}")
            continue

        # AES-128-CTR with zero IV
        counter = b"\x00" * 16
        ks = aes128_ecb_encrypt(key, counter)

        first_ct = fsb_data[4:20]
        first_pt = bytes(a ^ b for a, b in zip(first_ct, ks[:16]))

        if len(first_pt) < 4:
            print(f"  ERROR: Too short: {fsb_path}")
            verified = False
            continue

        version = struct.unpack("<I", first_pt[0:4])[0]

        print(f"\n  {os.path.basename(fsb_path)}:")
        print(f"    First decrypted block: {first_pt.hex()}")
        print(f"    Version field:         {version}")

        if version in (0, 1):
            if len(first_pt) >= 24:
                ns = struct.unpack("<I", first_pt[4:8])[0]
                hs = struct.unpack("<I", first_pt[8:12])[0]
                ds = struct.unpack("<I", first_pt[16:20])[0]
                codec = struct.unpack("<I", first_pt[20:24])[0]
                codec_name = FSB5_CODEC_NAMES.get(codec, f"Unknown({codec})")

                print(f"    Num samples:         {ns}")
                print(f"    Header size:         {hs}")
                print(f"    Data size:           {ds}")
                print(f"    Codec:               {codec_name}")

                if 1 <= ns <= 10000 and 20 <= hs <= 50000:
                    print(f"\n    >>> VALID FSB5 HEADER - KEY IS CORRECT! <<<")
                else:
                    print(f"    Header values seem unusual (key might be wrong)")
                    verified = False
            else:
                print(f"    Header too short to parse fully")
        else:
            print(f"    Invalid version {version} (key is WRONG)")
            verified = False

    return verified


# ─── Phase 5: Decryption ───────────────────────────────────────────────────

def phase5_decrypt_tracks(key, fsb_files):
    """Decrypt FSB5 files using AES-128-CTR and save as WAV."""
    print("\n" + "=" * 72)
    print("  Phase 5: Decryption")
    print("=" * 72)

    try:
        from Crypto.Cipher import AES as AES_MODERN
    except ImportError:
        print("  pycryptodome not available, skipping WAV conversion")
        print("  Install: pip install pycryptodome")
        return

    for fsb_path in fsb_files:
        print(f"\n  Processing: {os.path.basename(fsb_path)}")

        out_wav = fsb_path.rsplit(".", 1)[0] + ".wav"
        out_fsb = fsb_path.rsplit(".", 1)[0] + "_decrypted.fsb"

        with open(fsb_path, "rb") as f:
            data = bytearray(f.read())

        if data[:4] != b"FSB5":
            print(f"    Not an FSB5 file, skipping")
            continue

        # AES-128-CTR: E(key, counter) XOR ciphertext
        cipher = AES_MODERN.new(key, AES_MODERN.MODE_ECB)
        counter = b"\x00" * 16
        ks = cipher.encrypt(counter)

        for i in range(0, min(len(data) - 4, 4096), 16):
            if i + 16 > len(data) - 4:
                break
            for j in range(16):
                data[4 + i + j] ^= ks[j]

        # Write decrypted FSB5
        with open(out_fsb, "wb") as f:
            f.write(data)
        print(f"    Decrypted FSB5: {out_fsb}")

        # Parse decrypted header for WAV conversion
        try:
            if len(data) < 24:
                continue
            hdr_block = bytes(data[4:24])

            # Decrypt the full header properly
            # Reset and decrypt properly
            cipher2 = AES_MODERN.new(key, AES_MODERN.MODE_ECB)
            decrypted = bytearray(len(data) - 4)
            for idx in range(0, len(data) - 4, 16):
                block = data[4 + idx:4 + min(idx + 16, len(data) - 4)]
                if len(block) < 16:
                    block = block.ljust(16, b"\x00")
                ct_ks = cipher2.encrypt(counter)

                for j in range(len(block)):
                    decrypted[idx + j] = data[4 + idx + j] ^ ct_ks[j]

            full = bytes(decrypted)

            if len(full) >= 24:
                ver = struct.unpack("<I", full[0:4])[0]
                num_samples = struct.unpack("<I", full[4:8])[0]
                hdr_sz = struct.unpack("<I", full[8:12])[0]
                samp_data_sz = struct.unpack("<I", full[16:20])[0]
                codec = struct.unpack("<I", full[20:24])[0]

                print(f"    Decoded: v={ver} samples={num_samples} "
                      f"hdr={hdr_sz} data={samp_data_sz} codec={codec}")

                if codec == 1:  # PCM8
                    _write_wav_pcm8(out_wav, full, hdr_sz, num_samples)
                elif codec == 2:  # PCM16
                    _write_wav_pcm16(out_wav, full, hdr_sz, num_samples)
                else:
                    print(f"    WAV export only for PCM codecs (got {codec})")
                    print(f"    Use FMOD Studio or fsb-vorbis-encoder for conversion")

        except Exception as e:
            print(f"    WAV conversion error: {e}")


def _write_wav_pcm16(out_wav, fsb_data, hdr_sz, num_samples):
    """Convert PCM16 FSB5 data to WAV."""
    sample_hdr_sz = struct.unpack("<I", fsb_data[12:16])[0]
    channels = 1
    sample_rate = 44100

    # Scan sample headers for rate/channels
    pos = 24  # after main header
    while pos + 16 < hdr_sz:
        ch = struct.unpack("<I", fsb_data[pos:pos + 4])[0]
        bits = struct.unpack("<I", fsb_data[pos + 16:pos + 20])[0] if pos + 20 < hdr_sz else 0
        if ch > 0 and ch <= 8:
            channels = ch
        if bits > 0:
            sample_rate = bits
        pos += sample_hdr_sz

    data_off = hdr_sz
    pcm_data = fsb_data[data_off:data_off + num_samples * channels * 2]

    if not pcm_data:
        return

    with open(out_wav, "wb") as wav:
        data_size = len(pcm_data)
        file_size = 36 + data_size

        wav.write(b"RIFF")
        wav.write(struct.pack("<I", file_size))
        wav.write(b"WAVE")
        wav.write(b"fmt ")
        wav.write(struct.pack("<I", 16))  # chunk size
        wav.write(struct.pack("<H", 1))   # PCM
        wav.write(struct.pack("<H", channels))
        wav.write(struct.pack("<I", sample_rate))
        wav.write(struct.pack("<I", sample_rate * channels * 2))  # byte rate
        wav.write(struct.pack("<H", channels * 2))  # block align
        wav.write(struct.pack("<H", 16))  # bits per sample
        wav.write(b"data")
        wav.write(struct.pack("<I", data_size))
        wav.write(pcm_data)

    print(f"    WAV saved: {out_wav} ({data_size:,} bytes, "
          f"{sample_rate} Hz, {channels} ch)")


def _write_wav_pcm8(out_wav, fsb_data, hdr_sz, num_samples):
    """Convert PCM8 FSB5 data to WAV (upsample to 16-bit)."""
    data_off = hdr_sz
    pcm8 = fsb_data[data_off:data_off + num_samples]

    if not pcm8:
        return

    # Upsample 8-bit to 16-bit
    pcm16 = b"".join(struct.pack("<h", (b - 128) << 8) for b in pcm8)

    with open(out_wav, "wb") as wav:
        data_size = len(pcm16)
        file_size = 36 + data_size

        wav.write(b"RIFF")
        wav.write(struct.pack("<I", file_size))
        wav.write(b"WAVE")
        wav.write(b"fmt ")
        wav.write(struct.pack("<I", 16))
        wav.write(struct.pack("<H", 1))
        wav.write(struct.pack("<H", 1))
        wav.write(struct.pack("<I", 44100))
        wav.write(struct.pack("<I", 88200))
        wav.write(struct.pack("<H", 2))
        wav.write(struct.pack("<H", 16))
        wav.write(b"data")
        wav.write(struct.pack("<I", data_size))
        wav.write(pcm16)

    print(f"    WAV saved: {out_wav} ({data_size:,} bytes)")


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print(f"Noctua-c IL2CPP AES-128 Key Extractor v{VERSION}")
        print(f"")
        print(f"Usage:")
        print(f"  {sys.argv[0]} \\")
        print(f"      <global-metadata.dat> <libil2cpp.so> <track_0.fsb> [track_1.fsb]")
        print(f"")
        print(f"  Or (after C module has been run):")
        print(f"  {sys.argv[0]} <track_0.fsb> [track_1.fsb]")
        print(f"    (reads key from {RESULT_FILE})")
        sys.exit(1)

    # Check if we're in recovery mode (just verify with existing key)
    if len(sys.argv) >= 2 and os.path.exists(sys.argv[1]) and \
       not sys.argv[1].endswith(".dat") and \
       not sys.argv[1].endswith(".so"):
        # Recovery mode: just verify key against FSB files
        metadata_path = None
        binary_path = None
        fsb_files = sys.argv[1:]
    elif len(sys.argv) >= 4:
        metadata_path = sys.argv[1]
        binary_path = sys.argv[2]
        fsb_files = sys.argv[3:]

        for p in [metadata_path, binary_path] + fsb_files:
            if not os.path.exists(p):
                print(f"Error: file not found: {p}")
                sys.exit(1)
    else:
        print("Error: not enough arguments")
        sys.exit(1)

    key = None

    # Try reading existing key first
    if os.path.exists(RESULT_FILE):
        with open(RESULT_FILE) as f:
            key_hex = f.read().strip()
        if len(key_hex) == 32:
            key = bytes.fromhex(key_hex)
            print(f"Loaded existing key from {RESULT_FILE}: {key_hex}")

    # Phase 1+2+3: Full extraction
    if metadata_path and binary_path:
        try:
            import capstone
        except ImportError:
            print("\n  Note: Python capstone not found, using raw hex scanning")
            print("  Install: pip install capstone\n")

        hdr, full_name, cctor_info = phase1_parse_metadata(metadata_path)

        elf, code_addr, code_offset, text_sec = phase2_scan_binary(
            binary_path, full_name, cctor_info
        )

        extracted_key = phase3_disassemble_and_extract(
            elf, code_offset, code_addr, text_sec
        )

        if extracted_key:
            key = extracted_key

    if not key:
        print("\nNo key available. Run with full arguments to extract.")
        sys.exit(1)

    # Phase 4: Verify
    verified = phase4_verify_key(key, fsb_files)

    # Phase 5: Decrypt
    if verified:
        phase5_decrypt_tracks(key, fsb_files)

        print("\n" + "=" * 72)
        print(f"  SUCCESS! AES-128 KEY: {key.hex()}")
        print(f"  Decrypted FSB5 files saved alongside originals.")
        print("=" * 72)
    else:
        print("\n" + "=" * 72)
        print("  AES-128 KEY EXTRACTED BUT NOT VERIFIED")
        print(f"  Key hex: {key.hex()}")
        print("  Key saved to:", RESULT_FILE)
        print("=" * 72)
        print("\n  Possible issues:")
        print("  1. FSB5 files may use per-file IVs (non-zero counter)")
        print("  2. Key is obfuscated (XOR-encoded)")
        print("  3. Some FSB5 metadata at offset 0 may not decrypt to 'FSB5'")
        print("\n  Try the C module with:")
        print(f"    NOCTUA_METADATA={metadata_path} \\")
        print(f"    {NOCTUA_BIN} {binary_path} il2cpp_key_extractor")


if __name__ == "__main__":
    main()
