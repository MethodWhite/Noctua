"""
Minimal valid DEX file builder for testing DEXParser.
Creates DEX files with correct structure so the parser can read them.
"""
import struct, os, hashlib, zlib


class DexBuilder:
    """Build a valid .dex file from string/type/proto/method/class definitions."""

    def __init__(self):
        self.string_pool = []
        self.string_map = {}  # string -> index
        self.type_pool = []
        self.type_map = {}    # type string -> index in type_pool
        self.proto_list = []
        self.field_list = []
        self.method_list = []
        self.class_list = []
        self.field_id_list = []
        self.method_id_list = []
        self.class_def_list = []

    def intern_string(self, s):
        if s not in self.string_map:
            self.string_map[s] = len(self.string_pool)
            self.string_pool.append(s)
        return self.string_map[s]

    def intern_type(self, t):
        if t not in self.type_map:
            self.type_map[t] = len(self.type_pool)
            self.type_pool.append(t)
            self.intern_string(t)
        return self.type_map[t]

    def add_proto(self, shorty, return_type, param_types=None):
        self.intern_string(shorty)
        ret_idx = self.intern_type(return_type)
        params_start = 0
        self.proto_list.append({
            'shorty_idx': self.string_map[shorty],
            'return_idx': ret_idx,
            'params_off': params_start,
        })
        return len(self.proto_list) - 1

    def add_method(self, class_type, name, proto_idx=0):
        class_idx = self.intern_type(class_type)
        name_idx = self.intern_string(name)
        self.method_id_list.append((class_idx, proto_idx, name_idx))

    def add_class(self, class_type, superclass='Ljava/lang/Object;', access_flags=1):
        class_idx = self.intern_type(class_type)
        super_idx = self.intern_type(superclass)
        self.class_def_list.append({
            'class_idx': class_idx,
            'access_flags': access_flags,
            'superclass_idx': super_idx,
            'interfaces_off': 0,
            'source_file_idx': 0xFFFFFFFF,
            'annotations_off': 0,
            'class_data_off': 0,
            'static_values_off': 0,
        })

    def add_field(self, class_type, field_type, name):
        class_idx = self.intern_type(class_type)
        type_idx = self.intern_type(field_type)
        name_idx = self.intern_string(name)
        self.field_id_list.append((class_idx, type_idx, name_idx))

    def build(self):
        """Build complete DEX file bytes."""

        string_ids_size = len(self.string_pool)
        type_ids_size = len(self.type_pool)
        proto_ids_size = len(self.proto_list)
        field_ids_size = len(self.field_id_list)
        method_ids_size = len(self.method_id_list)
        class_defs_size = len(self.class_def_list)

        string_ids_off = 0x70
        type_ids_off = string_ids_off + string_ids_size * 4
        proto_ids_off = type_ids_off + type_ids_size * 4
        field_ids_off = proto_ids_off + proto_ids_size * 12
        method_ids_off = field_ids_off + field_ids_size * 8
        class_defs_off = method_ids_off + method_ids_size * 8

        # Build string data area
        string_data = bytearray()
        string_offsets = []
        for s in self.string_pool:
            string_offsets.append(len(string_data))
            encoded = s.encode('utf-8') + b'\x00'
            uleb = len(encoded) - 1
            while uleb > 0x7f:
                string_data.append((uleb & 0x7f) | 0x80)
                uleb >>= 7
            string_data.append(uleb & 0x7f)
            string_data.extend(encoded)

        data_off = (class_defs_off + class_defs_size * 32 + 3) & ~3
        file_size = data_off + len(string_data)

        buf = bytearray(file_size)

        # Header
        buf[0:4] = b'dex\n'
        buf[4:8] = b'035\x00'
        struct.pack_into('<I', buf, 8, 0)  # checksum placeholder
        buf[12:32] = b'\x00' * 20  # signature placeholder
        struct.pack_into('<I', buf, 32, file_size)
        struct.pack_into('<I', buf, 36, 0x70)
        struct.pack_into('<I', buf, 40, 0x12345678)  # endian tag
        struct.pack_into('<I', buf, 44, 0)   # link_size
        struct.pack_into('<I', buf, 48, 0)   # link_off
        struct.pack_into('<I', buf, 52, 0)   # map_off
        struct.pack_into('<I', buf, 56, string_ids_size)
        struct.pack_into('<I', buf, 60, string_ids_off)
        struct.pack_into('<I', buf, 64, type_ids_size)
        struct.pack_into('<I', buf, 68, type_ids_off)
        struct.pack_into('<I', buf, 72, proto_ids_size)
        struct.pack_into('<I', buf, 76, proto_ids_off)
        struct.pack_into('<I', buf, 80, field_ids_size)
        struct.pack_into('<I', buf, 84, field_ids_off)
        struct.pack_into('<I', buf, 88, method_ids_size)
        struct.pack_into('<I', buf, 92, method_ids_off)
        struct.pack_into('<I', buf, 96, class_defs_size)
        struct.pack_into('<I', buf, 100, class_defs_off)
        struct.pack_into('<I', buf, 104, len(string_data))
        struct.pack_into('<I', buf, 108, data_off)

        # String IDs
        for i, so in enumerate(string_offsets):
            struct.pack_into('<I', buf, string_ids_off + i * 4, data_off + so)

        # Type IDs
        for i, t in enumerate(self.type_pool):
            struct.pack_into('<I', buf, type_ids_off + i * 4, self.string_map[t])

        # Proto IDs
        for i, p in enumerate(self.proto_list):
            off = proto_ids_off + i * 12
            struct.pack_into('<I', buf, off, p['shorty_idx'])
            struct.pack_into('<I', buf, off + 4, p['return_idx'])
            struct.pack_into('<I', buf, off + 8, p['params_off'])

        # Field IDs
        for i, fi in enumerate(self.field_id_list):
            off = field_ids_off + i * 8
            struct.pack_into('<H', buf, off, fi[0])
            struct.pack_into('<H', buf, off + 2, fi[1])
            struct.pack_into('<I', buf, off + 4, fi[2])

        # Method IDs
        for i, mi in enumerate(self.method_id_list):
            off = method_ids_off + i * 8
            struct.pack_into('<H', buf, off, mi[0])
            struct.pack_into('<H', buf, off + 2, mi[1])
            struct.pack_into('<I', buf, off + 4, mi[2])

        # Class defs
        for i, c in enumerate(self.class_def_list):
            off = class_defs_off + i * 32
            struct.pack_into('<I', buf, off, c['class_idx'])
            struct.pack_into('<I', buf, off + 4, c['access_flags'])
            struct.pack_into('<I', buf, off + 8, c['superclass_idx'])
            struct.pack_into('<I', buf, off + 12, c['interfaces_off'])
            struct.pack_into('<I', buf, off + 16, c['source_file_idx'])
            struct.pack_into('<I', buf, off + 20, c['annotations_off'])
            struct.pack_into('<I', buf, off + 24, c['class_data_off'])
            struct.pack_into('<I', buf, off + 28, c['static_values_off'])

        # String data
        buf[data_off:data_off + len(string_data)] = string_data

        # SHA1 signature (bytes 12-31 are the sig, covers bytes 32..end)
        sha1 = hashlib.sha1(bytes(buf[32:])).digest()
        buf[12:32] = sha1

        # Adler32 checksum (bytes 8-11, covers bytes 12..end)
        adler = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
        struct.pack_into('<I', buf, 8, adler)

        return bytes(buf)


def create_whatsapp_dex_files(output_dir):
    """Create simulated WhatsApp DEX files with target class structures."""
    os.makedirs(output_dir, exist_ok=True)

    # classes.dex - Main classes with target structures
    b = DexBuilder()
    b.add_class('LX/4wQ;')
    b.add_class('LX/3DL;')
    b.add_class('LX/51Y;')
    b.add_class('Lorg/json/JSONObject;')
    b.add_class('Ljava/io/File;')
    b.add_class('Ljava/io/FileOutputStream;')
    b.add_class('Ljava/lang/Runtime;')
    b.add_class('Ljava/lang/reflect/Method;')
    b.add_class('Ljava/lang/reflect/Constructor;')
    b.add_class('Ldalvik/system/DexClassLoader;')
    b.add_class('Landroid/util/Log;')
    b.add_class('Ljava/nio/ByteBuffer;')
    b.add_class('[B')

    proto_void = b.add_proto('V', 'V')
    proto_string = b.add_proto('Ljava/lang/String;', 'Ljava/lang/String;')
    proto_void_string = b.add_proto('V', 'V')
    proto_boolean = b.add_proto('Z', 'Z')

    # LX/4wQ methods (12+)
    for mname in ['<init>', 'A01', 'A02', 'A03', 'B01', 'B02',
                  'fetchWebpMetadata', 'insertWebpMetadata',
                  'verifyWebpFileIntegrity', 'saveStickerToDisk',
                  'parseExifMetadata', 'writeExifMetadata',
                  'getStickerAttribute', 'setStickerAttribute',
                  'loadStickerFromPath']:
        b.add_method('LX/4wQ;', mname, proto_void)

    # LX/3DL methods (7+)
    for mname in ['<init>', 'A01', 'A02', 'B01', 'B02', 'B03',
                  'parseTiffIfd', 'processExifPayload']:
        b.add_method('LX/3DL;', mname, proto_void)

    # LX/51Y methods (7+)
    for mname in ['<init>', 'A01', 'A02', 'B01', 'B02', 'C01', 'C02',
                  'decodeAnimationFrame', 'processAnimationFrame',
                  'C03']:
        b.add_method('LX/51Y;', mname, proto_void)

    # Dangerous API references in classes2.dex
    for mname in ['exec', 'getRuntime', 'load', 'loadLibrary',
                  'createTempFile', 'delete', 'getAbsolutePath',
                  'getCanonicalPath', 'start', '<init>']:
        b.add_method('Ljava/lang/Runtime;', mname, proto_string)
        b.add_method('Ljava/io/File;', mname, proto_void_string)
        b.add_method('Ljava/lang/reflect/Method;', 'invoke', proto_void)
        b.add_method('Ljava/lang/reflect/Constructor;', 'newInstance', proto_void)
        b.add_method('Ldalvik/system/DexClassLoader;', '<init>', proto_void)

    # Add some fields
    b.add_field('LX/4wQ;', 'I', 'sticker_flags')
    b.add_field('LX/4wQ;', 'Ljava/lang/String;', 'sticker_metadata')
    b.add_field('LX/4wQ;', 'Ljava/lang/String;', 'exif_payload')
    b.add_field('LX/3DL;', 'I', 'tiff_ifd_count')
    b.add_field('LX/3DL;', '[B', 'tiff_data')
    b.add_field('LX/51Y;', 'I', 'frame_width')
    b.add_field('LX/51Y;', 'I', 'frame_height')
    b.add_field('LX/51Y;', 'I', 'frame_dispose')

    # Key strings
    for s in ['sticker_is_first_party', 'sticker_is_from_sticker_maker',
              'is-first-party-sticker', 'WA', '../', './', '/',
              'com.whatsapp.stickers', 'sticker_id', 'sticker_file_saved',
              'sticker_tmp_dir']:
        b.intern_string(s)

    dex_bytes = b.build()
    with open(os.path.join(output_dir, 'classes.dex'), 'wb') as f:
        f.write(dex_bytes)
    print(f"Created classes.dex ({len(dex_bytes)} bytes)")

    # classes2.dex - Additional dangerous APIs
    b2 = DexBuilder()
    b2.add_class('Ljava/lang/Runtime;')
    b2.add_class('Ljava/io/File;')
    b2.add_class('Ljava/lang/ProcessBuilder;')
    b2.add_class('Ldalvik/system/DexClassLoader;')
    b2.add_class('Ljava/lang/reflect/Method;')
    b2.add_class('Ljava/net/URL;')
    b2.add_class('Ljava/net/HttpURLConnection;')
    b2.add_method('Ljava/lang/Runtime;', 'exec')
    b2.add_method('Ljava/lang/Runtime;', 'getRuntime')
    b2.add_method('Ljava/lang/Runtime;', 'load')
    b2.add_method('Ljava/lang/Runtime;', 'loadLibrary')
    b2.add_method('Ljava/io/File;', 'createTempFile')
    b2.add_method('Ljava/io/File;', 'delete')
    b2.add_method('Ljava/lang/ProcessBuilder;', 'start')
    b2.add_method('Ldalvik/system/DexClassLoader;', '<init>')
    b2.intern_string('libwhatsapp.so')
    b2.intern_string('libstatic-webp.so')
    dex_bytes = b2.build()
    with open(os.path.join(output_dir, 'classes2.dex'), 'wb') as f:
        f.write(dex_bytes)
    print(f"Created classes2.dex ({len(dex_bytes)} bytes)")

    # classes3-11: Empty/minimal DEX files
    for i in range(3, 12):
        b = DexBuilder()
        b.add_class('Lcom/whatsapp/util/NoOp;')
        b.add_method('Lcom/whatsapp/util/NoOp;', '<init>')
        for j in range(5):
            b.intern_string(f'dummy_class_{i}_{j}')
        dex_bytes = b.build()
        with open(os.path.join(output_dir, f'classes{i}.dex'), 'wb') as f:
            f.write(dex_bytes)
        print(f"Created classes{i}.dex ({len(dex_bytes)} bytes)")

    print(f"\nCreated 11 DEX files in {output_dir}")


def build_minimal_dex(strings, types, protos, fields, methods, classes):
    """Legacy wrapper - use DexBuilder instead."""
    b = DexBuilder()
    for s in strings:
        b.intern_string(s)
    for t in types:
        b.intern_type(t)
    for p in protos:
        b.add_proto(p.get('shorty', 'V'), p.get('return_type', 'V'))
    proto_void = 0
    for m in methods:
        b.add_method(m.get('class', 'Ljava/lang/Object;'),
                     m.get('name', '<init>'), proto_void)
    for c in classes:
        b.add_class(c.get('name', 'Ljava/lang/Object;'),
                     c.get('superclass', 'Ljava/lang/Object;'),
                     c.get('access_flags', 1))
    # fields are stored but not used in legacy mode
    return b.build()


if __name__ == '__main__':
    create_whatsapp_dex_files('/tmp/opencode/whatsapp_dex')
