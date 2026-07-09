#!/usr/bin/env python3
"""
Il2Cpp Encryption Key Extractor
Scans global-metadata.dat and libil2cpp.so for AES encryption keys,
FMOD bank encryption keys, and other cryptographic material.

Usage:
    python tools/il2cpp_extract_key.py <global-metadata.dat> [libil2cpp.so]
"""

import struct
import sys
import math
import re
from collections import Counter

VERSION = "1.0.0"
IL2CPP_MAGIC = 0xFAB11BAF
IL2CPP_MAGIC_V2 = 0xFAB11BAF


def read_header(data):
    """Parse Il2CppGlobalMetadataHeader."""
    fields = [
        ("magic", 0), ("version", 4),
        ("stringLiteralOffset", 8), ("stringLiteralCount", 12),
        ("stringLiteralDataOffset", 16), ("stringLiteralDataSize", 20),
        ("stringOffset", 24), ("stringSize", 28),
        ("eventsOffset", 32), ("eventsCount", 36),
        ("propertiesOffset", 40), ("propertiesCount", 44),
        ("methodsOffset", 48), ("methodsSize", 52),
        ("parameterDefaultValuesOffset", 56), ("parameterDefaultValuesCount", 60),
        ("fieldDefaultValuesOffset", 64), ("fieldDefaultValuesCount", 68),
        ("fieldAndParameterDefaultValueDataOffset", 72),
        ("fieldAndParameterDefaultValueDataSize", 76),
        ("fieldMarshaledDataOffset", 80), ("fieldMarshaledDataCount", 84),
        ("parametersOffset", 88), ("parametersCount", 92),
        ("fieldsOffset", 96), ("fieldsCount", 100),
        ("fieldSwitchesOffset", 104), ("fieldSwitchesCount", 108),
        ("staticsOffset", 112), ("staticsCount", 116),
        ("typesOffset", 120), ("typesCount", 124),
        ("typeDefinitionsOffset", 128), ("typeDefinitionsCount", 132),
        ("genericStorageOffset", 136), ("genericStorageCount", 140),
        ("genericMethodRefsOffset", 144), ("genericMethodRefsCount", 148),
        ("genericInstsOffset", 152), ("genericInstsCount", 156),
        ("imageOffset", 160), ("imageCount", 164),
        ("assemblyOffset", 168), ("assemblyCount", 172),
        ("metadataUsageListsOffset", 176), ("metadataUsageListsCount", 180),
        ("metadataUsagePairsOffset", 184), ("metadataUsagePairsCount", 188),
        ("fieldDeclTypesOffset", 192), ("fieldDeclTypesCount", 196),
        ("typeHashesOffset", 200), ("typeHashesCount", 204),
    ]
    header = {}
    for name, off in fields:
        if off + 4 <= len(data):
            header[name] = struct.unpack_from("<I", data, off)[0]
    return header


def str_from_table(data, string_offset, string_size, idx):
    """Get a null-terminated string from the string table at byte offset idx."""
    if idx >= string_size:
        return f"<idx:{idx}>"
    end = data.find(b"\x00", string_offset + idx)
    if end == -1 or end - (string_offset + idx) > 1000:
        return f"<truncated:{idx}>"
    return data[string_offset + idx : end].decode("utf-8", errors="replace")


def scan_string_table(data, header):
    """Scan the string table for encryption-related strings."""
    string_off = header.get("stringOffset", 0)
    string_sz = header.get("stringSize", 0)
    if not string_off or not string_sz:
        return []

    blob = data[string_off : string_off + string_sz]
    results = []
    keywords = [
        "EncryptionKey", "encryptionKey", "encryption_key", "Encryption_Key",
        "AESKey", "aes_key", "AES_Key", "aesKey",
        "setEncryptionKey", "setEncryption",
        "FMOD", "fmod",
        "Encrypt128", "EncryptValue", "FinalEncrypt",
        "NewEncryptor", "CreateEncryptor", "CreateDecryptor",
        "EncryptData", "DecryptData",
    ]

    pos = 0
    while pos < len(blob):
        end = blob.find(b"\x00", pos)
        if end == -1 or end - pos > 1000:
            pos += 1
            continue
        s = blob[pos:end].decode("utf-8", errors="replace")
        for kw in keywords:
            if kw in s:
                results.append((string_off + pos, s, kw))
                break
        pos = end + 1
    return results


def scan_string_literals(data, header):
    """Scan string literal entries for encryption keys and hex patterns."""
    lit_off = header.get("stringLiteralOffset", 0)
    lit_count = header.get("stringLiteralCount", 0)
    lit_data_off = header.get("stringLiteralDataOffset", 0)
    lit_data_sz = header.get("stringLiteralDataSize", 0)

    if not lit_off or not lit_count:
        return []

    results = []
    for i in range(min(lit_count, 200000)):
        entry_off = lit_off + i * 8
        if entry_off + 8 > len(data):
            break
        data_idx = struct.unpack_from("<I", data, entry_off)[0]
        if data_idx >= lit_data_sz:
            continue

        str_off = lit_data_off + data_idx
        if str_off + 4 > len(data):
            continue
        str_len = struct.unpack_from("<I", data, str_off)[0]
        if str_len == 0 or str_len > 4096:
            continue
        if str_off + 4 + str_len * 2 > len(data):
            continue

        # Read as UTF-16
        raw = data[str_off + 4 : str_off + 4 + str_len * 2]
        try:
            u = raw.decode("utf-16-le", errors="replace")
        except:
            continue

        # Filter to printable ASCII
        ascii_str = "".join(c if 0x20 <= ord(c) <= 0x7E else "." for c in u[:256])
        ascii_str = ascii_str.rstrip(".")

        if len(ascii_str) < 4:
            continue

        # Check for encryption-related keywords
        s_lower = ascii_str.lower()
        if any(kw in s_lower for kw in
               ["encrypt", "decrypt", "aes", "key", "cipher",
                "crypto", "rijndael", "fmod", "bank", "iv=",
                "salt=", "password", "secret", "token"]):
            results.append(("KEYWORD", i, str_off, ascii_str))

        # Check for hex string (potential AES key)
        if all(c in "0123456789abcdefABCDEF" for c in ascii_str):
            if 16 <= len(ascii_str) <= 64:
                results.append(("HEX_KEY", i, str_off, ascii_str))

        # Check for base64 (potential AES key)
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                for c in ascii_str):
            if 20 <= len(ascii_str) <= 44 and "=" in ascii_str:
                results.append(("B64_KEY", i, str_off, ascii_str))

    return results


def scan_methods(data, header):
    """Scan methods for encryption-related functions."""
    methods_off = header.get("methodsOffset", 0)
    methods_sz = header.get("methodsSize", 0)
    string_off = header.get("stringOffset", 0)
    string_sz = header.get("stringSize", 0)

    if not methods_off or not methods_sz:
        return []

    entry_size = 36
    count = methods_sz // entry_size
    results = []

    keywords = [
        "Encrypt", "Decrypt", "AES", "Aes", "FMOD",
        "Cipher", "Crypto", "Rijndael", "EncryptionKey",
        "setEncryption", "Encrypt128", "EncryptValue",
        "EncryptData", "DecryptData",
    ]

    for i in range(min(count, 300000)):
        off = methods_off + i * entry_size
        if off + 4 > len(data):
            break
        name_idx = struct.unpack_from("<I", data, off)[0]
        name = str_from_table(data, string_off, string_sz, name_idx)

        for kw in keywords:
            if kw in name:
                method_idx = struct.unpack_from("<I", data, off + 20)[0]
                declaring_type = struct.unpack_from("<I", data, off + 4)[0]
                results.append((i, name, declaring_type, method_idx, kw))
                break

    return results


def scan_binary_for_keys(binary_path):
    """Scan the libil2cpp.so binary for AES keys and constants."""
    with open(binary_path, "rb") as f:
        data = f.read()

    results = {
        "strings": [],
        "symbols": [],
        "aes_sbox": None,
        "aes_rcon": None,
        "key_candidates": [],
    }

    # Search for encryption-related strings
    patterns = [
        b"EncryptionKey", b"encryptionKey", b"encryption_key",
        b"AESKey", b"aes_key", b"AES_Key",
        b"setEncryptionKey", b"setEncryption",
        b"FMOD", b"fmod_studio",
    ]
    for pat in patterns:
        idx = data.find(pat)
        if idx >= 0:
            results["strings"].append((idx, pat.decode("ascii", errors="replace")))
            # Try to get surrounding string context
            start = idx
            while start > 0 and data[start - 1] != 0:
                start -= 1
            end = idx
            while end < len(data) and data[end] != 0:
                end += 1
            results["strings"].append((start, data[start:end].decode("ascii", errors="replace")))

    # Check for AES S-box
    aes_sbox_start = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ])
    idx = data.find(aes_sbox_start)
    if idx >= 0:
        results["aes_sbox"] = idx

    # Check for AES Rcon
    aes_rcon = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])
    idx = data.find(aes_rcon)
    if idx >= 0:
        results["aes_rcon"] = idx

    # Check for AES inverse S-box
    aes_isbox_start = bytes([
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    ])
    idx = data.find(aes_isbox_start)
    if idx >= 0:
        results["aes_isbox"] = idx

    # Scan .rodata for potential 16-byte AES keys
    try:
        import elftools.elf.elffile as elf  # pyelftools
        elf_obj = elf.ELFFile(binary_path)
        for section in elf_obj.iter_sections():
            if section.name == ".rodata":
                rodata = section.data()
                for j in range(0, len(rodata) - 16, 1):
                    chunk = rodata[j : j + 16]
                    # Must have high entropy (>3.5 bits/byte)
                    freq = Counter(chunk)
                    entropy = -sum((c / 16) * math.log2(c / 16) for c in freq.values())
                    if entropy < 3.5:
                        continue
                    # Must not be all zeros, all ones, or ASCII
                    if all(b == 0 for b in chunk) or all(b == 0xFF for b in chunk):
                        continue
                    if all(0x20 <= b <= 0x7E for b in chunk):
                        continue
                    results["key_candidates"].append((section.header.sh_offset + j, chunk.hex(), entropy))
    except ImportError:
        # Fallback: scan for 16-byte aligned high-entropy data
        for j in range(0, len(data) - 16, 4):
            chunk = data[j : j + 16]
            if len(set(chunk)) < 4:
                continue
            if all(b == 0 for b in chunk) or all(b == 0xFF for b in chunk):
                continue
            if all(0x20 <= b <= 0x7E for b in chunk):
                continue
            freq = Counter(chunk)
            entropy = -sum((c / 16) * math.log2(c / 16) for c in freq.values())
            if entropy > 3.7:
                results["key_candidates"].append((j, chunk.hex(), entropy))

    # Deduplicate and sort
    seen = set()
    unique = []
    for off, val, ent in results["key_candidates"]:
        if val not in seen:
            seen.add(val)
            unique.append((off, val, ent))
    results["key_candidates"] = sorted(unique, key=lambda x: x[2], reverse=True)[:20]

    return results


def analyze_managed_dlls(apk_dir):
    """Try to find and analyze managed DLLs for encryption keys."""
    import os
    import zipfile

    results = []

    # Check if we're in an extracted APK directory
    managed_dir = os.path.join(apk_dir, "base", "assets", "bin", "Data", "Managed")
    if not os.path.exists(managed_dir):
        managed_dir = os.path.join(apk_dir, "assets", "bin", "Data", "Managed")
    if not os.path.exists(managed_dir):
        managed_dir = os.path.join(apk_dir, "Managed")
    if not os.path.exists(managed_dir):
        return results

    # Try to read DLLs for encryption-related strings
    keywords = rb"EncryptionKey|setEncryptionKey|AESKey|encryption_key|FMOD"
    for dll_name in os.listdir(managed_dir):
        if dll_name.endswith(".dll"):
            dll_path = os.path.join(managed_dir, dll_name)
            try:
                with open(dll_path, "rb") as f:
                    dll_data = f.read()
                for match in re.finditer(keywords, dll_data):
                    start = max(0, match.start() - 20)
                    end = min(len(dll_data), match.end() + 20)
                    context = dll_data[start:end]
                    # Extract readable string around match
                    ctx_str = ""
                    for b in context:
                        if 0x20 <= b <= 0x7E:
                            ctx_str += chr(b)
                        else:
                            ctx_str += "."
                    results.append((dll_name, match.start(), match.group().decode(), ctx_str))
            except (IOError, OSError):
                pass

    return results


def print_report(metadata_path, binary_path):
    """Generate a comprehensive report."""
    with open(metadata_path, "rb") as f:
        data = f.read()

    header = read_header(data)
    print(f"{'='*72}")
    print(f"  Il2Cpp Encryption Key Extractor v{VERSION}")
    print(f"{'='*72}\n")

    # Basic info
    magic = header.get("magic", 0)
    version = header.get("version", 0)
    valid = magic == IL2CPP_MAGIC or magic == IL2CPP_MAGIC_V2
    print(f"  Metadata file:    {metadata_path}")
    print(f"  Size:             {len(data):,} bytes ({len(data)/1048576:.1f} MB)")
    print(f"  Magic:            0x{magic:08X} {'[VALID]' if valid else '[INVALID]'}")
    print(f"  Version:          {version}")
    print(f"  String literals:  {header.get('stringLiteralCount', 0):,}")
    print(f"  String table:     {header.get('stringSize', 0):,} bytes")
    print(f"  Methods:          {header.get('methodsSize', 0) // 36:,}")
    print(f"  Types:            {header.get('typeDefinitionsCount', 0):,}")
    print()

    # Scan string table for encryption keywords
    print(f"  ── String Table Keyword Scan ──")
    string_hits = scan_string_table(data, header)
    if string_hits:
        print(f"  Found {len(string_hits)} encryption-related strings:")
        for off, s, kw in string_hits[:30]:
            print(f"    @0x{off:06x} [{kw}] {s[:120]}")
        if len(string_hits) > 30:
            print(f"    ... and {len(string_hits) - 30} more")
    else:
        print(f"  No encryption-related strings found in string table")
    print()

    # Scan string literals
    print(f"  ── String Literal Scan ──")
    lit_hits = scan_string_literals(data, header)
    categories = {}
    for cat, idx, off, s in lit_hits:
        categories.setdefault(cat, []).append((idx, off, s))

    for cat in ["KEYWORD", "HEX_KEY", "B64_KEY"]:
        hits = categories.get(cat, [])
        if hits:
            print(f"  [{cat}] {len(hits)} entries:")
            for idx, off, s in hits[:15]:
                print(f"    Lit[{idx:5d}] @0x{off:06x}: {s[:120]}")
            if len(hits) > 15:
                print(f"    ... and {len(hits) - 15} more")
    print()

    # Scan methods
    print(f"  ── Method Scan (Encryption/AES/FMOD) ──")
    methods = scan_methods(data, header)
    if methods:
        print(f"  Found {len(methods)} encryption-related methods:")
        for idx, name, dtype, midx, kw in methods[:30]:
            code_str = f"code@0x{midx:08x}" if midx != 0xFFFFFFFF else "no_native_code"
            print(f"    Method[{idx:5d}] type={dtype:5d} '{name}' [{kw}] {code_str}")
        if len(methods) > 30:
            print(f"    ... and {len(methods) - 30} more")
    else:
        print(f"  No encryption-related methods found")
    print()

    # Scan binary
    if binary_path:
        print(f"  ── Binary Analysis: {binary_path} ──")
        bin_results = scan_binary_for_keys(binary_path)

        if bin_results["strings"]:
            print(f"  Encryption-related strings:")
            seen = set()
            for off, s in bin_results["strings"]:
                if s not in seen:
                    seen.add(s)
                    print(f"    @0x{off:08x}: {s[:100]}")

        if bin_results["aes_sbox"]:
            print(f"  AES S-box found at 0x{bin_results['aes_sbox']:x}")
        else:
            print(f"  AES S-box: NOT FOUND (hardware AES likely used)")

        if bin_results["aes_rcon"]:
            print(f"  AES Rcon found at 0x{bin_results['aes_rcon']:x}")
        else:
            print(f"  AES Rcon: NOT FOUND (hardware AES likely used)")

        if bin_results["key_candidates"]:
            print(f"\n  Top AES key candidates (high-entropy 16-byte constants):")
            for off, val, ent in bin_results["key_candidates"][:10]:
                print(f"    @0x{off:08x} entropy={ent:.2f}: {val}")
        print()

    # Summary / finding
    print(f"  {'='*68}")
    print(f"  FINDINGS SUMMARY")
    print(f"  {'='*68}")

    has_fmod_methods = any("FMOD" in str(m) for m in methods)
    has_setencryptkey = any("setEncryption" in str(s[1]) or "setEncryption" in str(s[1])
                            for s in string_hits)
    has_aes_methods = any(
        kw in {"AES", "Aes", "Rijndael", "AesManaged"}
        for _, _, _, _, kw in methods
    )

    if has_fmod_methods or has_setencryptkey:
        print(f"\n  [!] FMOD bank encryption DETECTED!")
        print(f"  [!] The game uses FMOD Studio encrypted banks.")
        if has_setencryptkey:
            print(f"  [!] setEncryptionKey method found.")
    else:
        print(f"\n  [-] FMOD bank encryption: NOT DETECTED")

    if has_aes_methods:
        print(f"\n  [!] AES/Rijndael encryption DETECTED in methods.")
    else:
        print(f"\n  [-] AES managed methods: NOT FOUND in scanned range")

    # Check if encryption is purely managed
    all_methods_no_native = all(midx == 0xFFFFFFFF for _, _, _, midx, _ in methods)
    if methods and all_methods_no_native:
        print(f"\n  [!] All encryption methods have NO native code mapping.")
        print(f"  [!] Encryption is likely implemented in C# managed code.")
        print(f"  [!] The key will be in Assembly-CSharp.dll or dependencies.")
    elif methods:
        print(f"\n  [!] Some encryption methods have native code.")
        print(f"  [!] Key may be constructed at runtime.")

    hex_keys = [s for _, _, s in lit_hits if all(c in "0123456789abcdefABCDEF" for c in s)]
    if hex_keys:
        print(f"\n  [!] POTENTIAL AES KEY FOUND in string literal data!")
        for k in hex_keys[:5]:
            print(f"      '{k}' ({len(k)//2} bytes)")

    print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <global-metadata.dat> [libil2cpp.so]")
        print(f"  Scans Unity Il2Cpp metadata and binary for encryption keys.")
        sys.exit(1)

    metadata_path = sys.argv[1]
    binary_path = sys.argv[2] if len(sys.argv) > 2 else None

    if binary_path and not os.path.exists(binary_path):
        print(f"Warning: Binary file not found: {binary_path}")
        binary_path = None

    print_report(metadata_path, binary_path)


if __name__ == "__main__":
    import os
    main()
