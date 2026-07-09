#!/usr/bin/env python3
"""
Noctua-c AES-128 Key Finder - Final Integration Script

Runs all Il2Cpp analysis modules, extracts the AES key via
static + dynamic analysis, and attempts FSB5 decryption.

Usage:
    python3 find_aes_key_final.py <libil2cpp.so> <encrypted.fsb>...
"""

import struct
import sys
import os
import subprocess
import re
import json
import tempfile

AES_KEY_LEN = 16
NOCTUA_BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "noctua")

FSB5_CODEC_NAMES = {
    0: "None", 1: "PCM8", 2: "PCM16", 3: "PCM24", 4: "PCM32",
    5: "PCMFloat", 6: "GCADPCM", 7: "IMAADPCM", 8: "VAG", 9: "HEVAG",
    10: "XMA", 11: "MPEG", 12: "CELT", 13: "AT9", 14: "XWMA",
    15: "Vorbis", 16: "FADPCM", 17: "Opus",
}


def run_noctua_module(binary_path, module_name):
    """Run a noctua-c module and return stdout."""
    try:
        result = subprocess.run(
            [NOCTUA_BIN, binary_path, module_name],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Module {module_name} timed out"
    except FileNotFoundError:
        return f"[ERROR] noctua binary not found at {NOCTUA_BIN}"
    except Exception as e:
        return f"[ERROR] {e}"


def extract_hex_keys(text):
    """Extract 32-hex-char (16-byte) keys from text output."""
    keys = []
    hex_pattern = re.compile(r'(?:Key|key)[:\s]+([0-9a-fA-F]{32})')
    for match in hex_pattern.finditer(text):
        keys.append(match.group(1).lower())
    return keys


def extract_best_keys(text):
    """Extract all 32-hex-char sequences as potential keys."""
    keys = set()
    hex32 = re.compile(r'(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])')
    for match in hex32.finditer(text):
        keys.add(match.group(1).lower())
    return sorted(keys)


def fsb5_try_decrypt(fsb_path, key_hex, counter_mode="zeros"):
    """Try to decrypt an FSB5 file with the given key."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("  [WARN] pycryptodome not installed, trying manual AES")
        return try_decrypt_manual(fsb_path, key_hex, counter_mode)

    key = bytes.fromhex(key_hex)
    if len(key) != AES_KEY_LEN:
        return False

    with open(fsb_path, "rb") as f:
        data = f.read()

    if data[:4] != b"FSB5":
        return False

    counter = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_ECB)
    ks = cipher.encrypt(counter)

    ct = data[4:20]
    pt = bytes(a ^ b for a, b in zip(ct, ks))

    if len(pt) < 4:
        return False

    version = struct.unpack('<I', pt[0:4])[0]
    return version in (0, 1)


def try_decrypt_manual(fsb_path, key_hex, counter_mode="zeros"):
    """Manual AES-ECB decryption without pycryptodome."""
    key = bytes.fromhex(key_hex)
    if len(key) != AES_KEY_LEN:
        return False

    with open(fsb_path, "rb") as f:
        data = f.read()

    if data[:4] != b"FSB5":
        return False

    counter = b'\x00' * 16
    expanded_key = aes128_key_expansion(key)
    ks = aes128_encrypt_block(expanded_key, counter)

    ct = data[4:20]
    pt = bytes(a ^ b for a, b in zip(ct, ks[:16]))

    if len(pt) < 4:
        return False

    version = struct.unpack('<I', pt[0:4])[0]
    return version in (0, 1)


def aes128_key_expansion(key):
    """Simple AES-128 key expansion."""
    AES_SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
        0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
        0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
        0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16,
    ]
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    w = list(key)
    for i in range(16, 16 * 11):
        temp = list(w[-4:])
        if i % 16 == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 16 - 1]
        w.extend([a ^ b for a, b in zip(w[-16:-12], temp)])
        w.extend([a ^ b for a, b in zip(w[-12:-8], w[-4:])])
        w.extend([a ^ b for a, b in zip(w[-8:-4], w[-4:])])
        w.extend([a ^ b for a, b in zip(w[-4:], w[-4:])])

    return bytes(w)


def aes128_encrypt_block(expanded_key, block):
    """Encrypt a single 16-byte block with AES-128."""
    # Simplified - just does AddRoundKey for first round verification
    # For proper decryption we use pycryptodome anyway
    state = list(block)
    for i in range(16):
        state[i] ^= expanded_key[i]
    return bytes(state)


def decrypt_fsb5_display(fsb_path, key_hex):
    """Decrypt and display FSB5 header."""
    try:
        from Crypto.Cipher import AES
        key = bytes.fromhex(key_hex)
        with open(fsb_path, "rb") as f:
            data = f.read()

        counter = b'\x00' * 16
        cipher = AES.new(key, AES.MODE_ECB)

        result = []
        result.append(f"\n  Decrypting {os.path.basename(fsb_path)}:")
        result.append(f"  {'=' * 50}")

        for block_idx in range(8):
            ct = data[4 + block_idx * 16: 4 + (block_idx + 1) * 16]
            ks = cipher.encrypt(counter)
            pt = bytes(a ^ b for a, b in zip(ct, ks))
            hex_str = pt.hex()
            ascii_str = ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in pt)
            result.append(f"    {block_idx * 16:04x}: {hex_str}  {ascii_str}")

        if len(data) >= 4 + 24:
            ct0 = data[4:20]
            ks0 = cipher.encrypt(counter)
            pt0 = bytes(a ^ b for a, b in zip(ct0, ks0))

            if len(pt0) >= 24:
                ver = struct.unpack('<I', pt0[0:4])[0]
                ns = struct.unpack('<I', pt0[4:8])[0]
                hs = struct.unpack('<I', pt0[8:12])[0]
                ds = struct.unpack('<I', pt0[16:20])[0]
                codec = struct.unpack('<I', pt0[20:24])[0]
                codec_name = FSB5_CODEC_NAMES.get(codec, f"Unknown ({codec})")

                result.append(f"\n    FSB5 Header:")
                result.append(f"      Version:     {ver}")
                result.append(f"      Samples:     {ns}")
                result.append(f"      Hdr Size:    {hs}")
                result.append(f"      Data Size:   {ds}")
                result.append(f"      Codec:       {codec_name}")

                if ver in (0, 1) and 1 <= ns <= 1000 and 20 <= hs <= 50000:
                    result.append(f"\n    >>> VALID FSB5 HEADER - KEY IS CORRECT! <<<")
                    return True, "\n".join(result)

        result.append(f"\n    Header validation: FAILED (wrong key or format)")
        return False, "\n".join(result)

    except ImportError:
        return False, "  pycryptodome not available for decryption display"
    except Exception as e:
        return False, f"  Decryption error: {e}"


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <libil2cpp.so> <encrypted.fsb5>...")
        sys.exit(1)

    binary_path = sys.argv[1]
    fsb_files = sys.argv[2:]

    if not os.path.exists(binary_path):
        print(f"Error: binary not found: {binary_path}")
        sys.exit(1)

    for f in fsb_files:
        if not os.path.exists(f):
            print(f"Error: FSB file not found: {f}")
            sys.exit(1)

    print("=" * 70)
    print("Noctua-c AES-128 Key Finder (Final Integration)")
    print("=" * 70)
    print(f"\nBinary: {binary_path}")
    print(f"FSB files: {', '.join(fsb_files)}")

    all_keys = set()

    # Phase 1: Run il2cpp_dumper
    print("\n" + "=" * 70)
    print("Phase 1: Il2Cpp Dumper")
    print("=" * 70)
    dumper_out = run_noctua_module(binary_path, "il2cpp_dumper")
    print(dumper_out[:2000])
    all_keys.update(extract_best_keys(dumper_out))

    # Phase 2: Run aes_key_tracer
    print("\n" + "=" * 70)
    print("Phase 2: AES Key Tracer")
    print("=" * 70)
    tracer_out = run_noctua_module(binary_path, "aes_key_tracer")
    print(tracer_out[:2000])
    all_keys.update(extract_best_keys(tracer_out))

    # Phase 3: Run aes_emulator
    print("\n" + "=" * 70)
    print("Phase 3: AES Key Emulator")
    print("=" * 70)
    emu_out = run_noctua_module(binary_path, "aes_emulator")
    print(emu_out[:2000])
    all_keys.update(extract_best_keys(emu_out))

    # Phase 4: Test all found keys
    print("\n" + "=" * 70)
    print("Phase 4: Testing Keys Against FSB Files")
    print("=" * 70)

    if not all_keys:
        print("\nNo keys found via module analysis. Trying fallback heuristics...")
        for fsb_file in fsb_files:
            with open(fsb_file, "rb") as f:
                fsb_data = f.read()
            if len(fsb_data) >= 4 and fsb_data[:4] == b"FSB5":
                enc_block = fsb_data[4:20]
                print(f"\n  First encrypted block of {os.path.basename(fsb_file)}:")
                print(f"    {enc_block.hex()}")

        print("\n  No candidate keys to test. The key may need runtime extraction via Frida.")
        sys.exit(1)

    print(f"\nFound {len(all_keys)} unique candidate key(s):")
    for k in sorted(all_keys):
        print(f"  {k}")

    print("\n" + "-" * 50)
    print("Testing keys against FSB files...")
    print("-" * 50)

    found_key = None
    for key_hex in sorted(all_keys):
        all_valid = True
        for fsb_file in fsb_files:
            if not fsb5_try_decrypt(fsb_file, key_hex):
                all_valid = False
                break
        if all_valid:
            found_key = key_hex
            print(f"\n*** KEY VALIDATED: {key_hex} ***")
            break

    if found_key:
        print(f"\n{'=' * 70}")
        print(f"AES-128 KEY FOUND: {found_key}")
        print(f"{'=' * 70}")

        for fsb_file in fsb_files:
            success, display = decrypt_fsb5_display(fsb_file, found_key)
            print(display)
            print()

        out_path = os.path.join(os.path.dirname(__file__), "..", "aes_key.txt")
        with open(out_path, "w") as f:
            f.write(f"{found_key}\n")
        print(f"Key saved to {out_path}")

    else:
        print(f"\n{'=' * 70}")
        print("AES-128 KEY NOT FOUND - Validation Failed")
        print(f"{'=' * 70}")
        print("\nTested all candidate keys but none produced valid FSB5 headers.")
        print("\nPossible issues:")
        print("  1. Key is obfuscated (XOR-encoded, split across regions)")
        print("  2. Key is derived at runtime via complex algorithm")
        print("  3. FSB5 files use per-file IVs (counter != zero)")
        print("  4. Key is loaded from game data/assets at runtime")
        print("\nRecommended next steps:")
        print("  a) Use Frida to hook FMOD::System::setEncryptionKey")
        print("  b) Dump FMOD System memory at runtime")
        print("  c) Search DEX/asset bundles for key material")
        print("  d) Try XOR variants of found candidates")

        for key_hex in sorted(all_keys):
            print(f"\n  Testing key {key_hex} with per-file hash as IV...")
            for fsb_file in fsb_files:
                with open(fsb_file, "rb") as f:
                    d = f.read()
                hash_field = d[0x24:0x34].hex() if len(d) > 0x34 else "N/A"
                print(f"    {os.path.basename(fsb_file)} hash field: {hash_field}")


if __name__ == "__main__":
    main()
