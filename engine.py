import os, struct, hashlib, logging

class MWREEngine:
    def __init__(self, path):
        self.path = path
        self.data = None
        self.parsed = {}
        self.type = None

    def run(self):
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"File not found: {self.path}")
        with open(self.path, 'rb') as f:
            self.data = f.read()
        if self.data[:4] == b'dex\n':
            self.type = 'dex'
            self._parse_dex()
        elif self.data[:4] == b'RIFF':
            self.type = 'webp'
            self._parse_webp()
        elif self.data[:2] == b'MZ':
            self.type = 'pe'
        elif self.data[:4] == b'\x7fELF':
            self.type = 'elf'
        else:
            self.type = 'raw'

    def _parse_dex(self):
        if len(self.data) < 0x70:
            return
        self.parsed['header'] = {}
        h = self.parsed['header']
        h['checksum'] = struct.unpack_from('<I', self.data, 8)[0]
        h['signature'] = self.data[12:32]
        h['file_size'] = struct.unpack_from('<I', self.data, 32)[0]
        h['header_size'] = struct.unpack_from('<I', self.data, 36)[0]
        h['endian_tag'] = struct.unpack_from('<I', self.data, 40)[0]
        h['link_size'] = struct.unpack_from('<I', self.data, 44)[0]
        h['link_off'] = struct.unpack_from('<I', self.data, 48)[0]
        h['map_off'] = struct.unpack_from('<I', self.data, 52)[0]
        h['string_ids_size'] = struct.unpack_from('<I', self.data, 56)[0]
        h['string_ids_off'] = struct.unpack_from('<I', self.data, 60)[0]
        h['type_ids_size'] = struct.unpack_from('<I', self.data, 64)[0]
        h['type_ids_off'] = struct.unpack_from('<I', self.data, 68)[0]
        h['proto_ids_size'] = struct.unpack_from('<I', self.data, 72)[0]
        h['proto_ids_off'] = struct.unpack_from('<I', self.data, 76)[0]
        h['field_ids_size'] = struct.unpack_from('<I', self.data, 80)[0]
        h['field_ids_off'] = struct.unpack_from('<I', self.data, 84)[0]
        h['method_ids_size'] = struct.unpack_from('<I', self.data, 88)[0]
        h['method_ids_off'] = struct.unpack_from('<I', self.data, 92)[0]
        h['class_defs_size'] = struct.unpack_from('<I', self.data, 96)[0]
        h['class_defs_off'] = struct.unpack_from('<I', self.data, 100)[0]
        h['data_size'] = struct.unpack_from('<I', self.data, 104)[0]
        h['data_off'] = struct.unpack_from('<I', self.data, 108)[0]

        self.parsed['strings'] = self._parse_strings()
        self.parsed['types'] = self._parse_types()
        self.parsed['protos'] = self._parse_protos()
        self.parsed['fields'] = self._parse_fields()
        self.parsed['methods'] = self._parse_methods()
        self.parsed['classes'] = self._parse_classes()

    def _parse_strings(self):
        off = self.parsed['header']['string_ids_off']
        count = self.parsed['header']['string_ids_size']
        strings = []
        for i in range(count):
            if off + i * 4 + 4 > len(self.data):
                break
            str_off = struct.unpack_from('<I', self.data, off + i * 4)[0]
            if str_off >= len(self.data):
                strings.append('')
                continue
            end = self.data.index(0, str_off) if 0 in self.data[str_off:] else len(self.data)
            try:
                strings.append(self.data[str_off:end].decode('utf-8', errors='replace'))
            except:
                strings.append('')
        return strings

    def _parse_types(self):
        off = self.parsed['header']['type_ids_off']
        count = self.parsed['header']['type_ids_size']
        types = []
        for i in range(count):
            if off + i * 4 + 4 > len(self.data):
                break
            idx = struct.unpack_from('<I', self.data, off + i * 4)[0]
            s = self.parsed['strings'][idx] if idx < len(self.parsed['strings']) else ''
            types.append(s)
        return types

    def _parse_protos(self):
        off = self.parsed['header']['proto_ids_off']
        count = self.parsed['header']['proto_ids_size']
        protos = []
        sz = 12
        for i in range(count):
            if off + i * sz + sz > len(self.data):
                break
            shorty_idx = struct.unpack_from('<I', self.data, off + i * sz)[0]
            ret_type_idx = struct.unpack_from('<I', self.data, off + i * sz + 4)[0]
            param_idx = struct.unpack_from('<I', self.data, off + i * sz + 8)[0]
            protos.append({
                'shorty': self.parsed['strings'][shorty_idx] if shorty_idx < len(self.parsed['strings']) else '',
                'return_type': self.parsed['types'][ret_type_idx] if ret_type_idx < len(self.parsed['types']) else '',
                'params_off': param_idx,
            })
        return protos

    def _parse_fields(self):
        off = self.parsed['header']['field_ids_off']
        count = self.parsed['header']['field_ids_size']
        fields = []
        sz = 8
        for i in range(count):
            if off + i * sz + sz > len(self.data):
                break
            class_idx = struct.unpack_from('<H', self.data, off + i * sz)[0]
            type_idx = struct.unpack_from('<H', self.data, off + i * sz + 2)[0]
            name_idx = struct.unpack_from('<I', self.data, off + i * sz + 4)[0]
            fields.append({
                'class': self.parsed['types'][class_idx] if class_idx < len(self.parsed['types']) else '',
                'type': self.parsed['types'][type_idx] if type_idx < len(self.parsed['types']) else '',
                'name': self.parsed['strings'][name_idx] if name_idx < len(self.parsed['strings']) else '',
            })
        return fields

    def _parse_methods(self):
        off = self.parsed['header']['method_ids_off']
        count = self.parsed['header']['method_ids_size']
        methods = []
        sz = 8
        for i in range(count):
            if off + i * sz + sz > len(self.data):
                break
            class_idx = struct.unpack_from('<H', self.data, off + i * sz)[0]
            proto_idx = struct.unpack_from('<H', self.data, off + i * sz + 2)[0]
            name_idx = struct.unpack_from('<I', self.data, off + i * sz + 4)[0]
            methods.append({
                'class': self.parsed['types'][class_idx] if class_idx < len(self.parsed['types']) else '',
                'proto': self.parsed['protos'][proto_idx] if proto_idx < len(self.parsed['protos']) else {},
                'name': self.parsed['strings'][name_idx] if name_idx < len(self.parsed['strings']) else '',
            })
        return methods

    def _parse_classes(self):
        off = self.parsed['header']['class_defs_off']
        count = self.parsed['header']['class_defs_size']
        classes = []
        sz = 32
        for i in range(count):
            if off + i * sz + sz > len(self.data):
                break
            class_idx = struct.unpack_from('<I', self.data, off + i * sz)[0]
            access_flags = struct.unpack_from('<I', self.data, off + i * sz + 4)[0]
            superclass_idx = struct.unpack_from('<I', self.data, off + i * sz + 8)[0]
            interfaces_off = struct.unpack_from('<I', self.data, off + i * sz + 12)[0]
            source_file_idx = struct.unpack_from('<I', self.data, off + i * sz + 16)[0]
            annotations_off = struct.unpack_from('<I', self.data, off + i * sz + 20)[0]
            class_data_off = struct.unpack_from('<I', self.data, off + i * sz + 24)[0]
            static_values_off = struct.unpack_from('<I', self.data, off + i * sz + 28)[0]
            name = self.parsed['types'][class_idx] if class_idx < len(self.parsed['types']) else ''
            superclass = self.parsed['types'][superclass_idx] if superclass_idx < len(self.parsed['types']) else ''
            classes.append({
                'name': name,
                'access_flags': access_flags,
                'superclass': superclass,
                'class_data_off': class_data_off,
            })
        return classes

    def _parse_webp(self):
        if len(self.data) < 12:
            return
        self.parsed['riff_size'] = struct.unpack_from('<I', self.data, 4)[0]
        self.parsed['webp_type'] = self.data[8:12].decode('ascii', errors='replace')
        self.parsed['chunks'] = []
        pos = 12
        while pos + 8 <= len(self.data):
            chunk_id = self.data[pos:pos+4].decode('ascii', errors='replace')
            chunk_size = struct.unpack_from('<I', self.data, pos+4)[0]
            chunk_data = self.data[pos+8:pos+8+chunk_size]
            self.parsed['chunks'].append({
                'id': chunk_id,
                'size': chunk_size,
                'offset': pos,
                'data_len': len(chunk_data),
            })
            pos += 8 + chunk_size
            if chunk_size & 1:
                pos += 1

    def summary(self):
        return {
            'path': self.path,
            'size': len(self.data) if self.data else 0,
            'type': self.type,
            'parsed_keys': list(self.parsed.keys()),
        }
