import struct, logging

OPCODES = {
    0x00: 'NOP', 0x01: 'MOVE', 0x02: 'MOVE_FROM16', 0x03: 'MOVE_16',
    0x04: 'MOVE_WIDE', 0x05: 'MOVE_WIDE_FROM16', 0x06: 'MOVE_WIDE_16',
    0x07: 'MOVE_OBJECT', 0x08: 'MOVE_OBJECT_FROM16', 0x09: 'MOVE_OBJECT_16',
    0x0a: 'MOVE_RESULT', 0x0b: 'MOVE_RESULT_WIDE', 0x0c: 'MOVE_RESULT_OBJECT',
    0x0d: 'MOVE_EXCEPTION', 0x0e: 'RETURN_VOID', 0x0f: 'RETURN',
    0x10: 'RETURN_WIDE', 0x11: 'RETURN_OBJECT', 0x12: 'CONST_4',
    0x13: 'CONST_16', 0x14: 'CONST', 0x15: 'CONST_HIGH16',
    0x16: 'CONST_WIDE_16', 0x17: 'CONST_WIDE_32', 0x18: 'CONST_WIDE',
    0x19: 'CONST_WIDE_HIGH16', 0x1a: 'CONST_STRING', 0x1b: 'CONST_STRING_JUMBO',
    0x1c: 'CONST_CLASS', 0x1d: 'MONITOR_ENTER', 0x1e: 'MONITOR_EXIT',
    0x1f: 'CHECK_CAST', 0x20: 'INSTANCE_OF', 0x21: 'ARRAY_LENGTH',
    0x22: 'NEW_INSTANCE', 0x23: 'NEW_ARRAY', 0x24: 'FILLED_NEW_ARRAY',
    0x25: 'FILLED_NEW_ARRAY_RANGE', 0x26: 'FILL_ARRAY_DATA',
    0x27: 'THROW', 0x28: 'GOTO', 0x29: 'GOTO_16', 0x2a: 'GOTO_32',
    0x2b: 'PACKED_SWITCH', 0x2c: 'SPARSE_SWITCH',
    0x2d: 'CMPL_FLOAT', 0x2e: 'CMPG_FLOAT', 0x2f: 'CMPL_DOUBLE',
    0x30: 'CMPG_DOUBLE', 0x31: 'CMP_LONG', 0x32: 'IF_EQ',
    0x33: 'IF_NE', 0x34: 'IF_LT', 0x35: 'IF_GE', 0x36: 'IF_GT',
    0x37: 'IF_LE', 0x38: 'IF_EQZ', 0x39: 'IF_NEZ', 0x3a: 'IF_LTZ',
    0x3b: 'IF_GEZ', 0x3c: 'IF_GTZ', 0x3d: 'IF_LEZ',
    0x3e: 'AGET', 0x3f: 'AGET_WIDE', 0x40: 'AGET_OBJECT', 0x41: 'AGET_BOOLEAN',
    0x42: 'AGET_BYTE', 0x43: 'AGET_CHAR', 0x44: 'AGET_SHORT',
    0x45: 'APUT', 0x46: 'APUT_WIDE', 0x47: 'APUT_OBJECT', 0x48: 'APUT_BOOLEAN',
    0x49: 'APUT_BYTE', 0x4a: 'APUT_CHAR', 0x4b: 'APUT_SHORT',
    0x4c: 'IGET', 0x4d: 'IGET_WIDE', 0x4e: 'IGET_OBJECT', 0x4f: 'IGET_BOOLEAN',
    0x50: 'IGET_BYTE', 0x51: 'IGET_CHAR', 0x52: 'IGET_SHORT',
    0x53: 'IPUT', 0x54: 'IPUT_WIDE', 0x55: 'IPUT_OBJECT', 0x56: 'IPUT_BOOLEAN',
    0x57: 'IPUT_BYTE', 0x58: 'IPUT_CHAR', 0x59: 'IPUT_SHORT',
    0x5a: 'SGET', 0x5b: 'SGET_WIDE', 0x5c: 'SGET_OBJECT',
    0x5d: 'SGET_BOOLEAN', 0x5e: 'SGET_BYTE', 0x5f: 'SGET_CHAR', 0x60: 'SGET_SHORT',
    0x61: 'SPUT', 0x62: 'SPUT_WIDE', 0x63: 'SPUT_OBJECT',
    0x64: 'SPUT_BOOLEAN', 0x65: 'SPUT_BYTE', 0x66: 'SPUT_CHAR', 0x67: 'SPUT_SHORT',
    0x68: 'INVOKE_VIRTUAL', 0x69: 'INVOKE_SUPER', 0x6a: 'INVOKE_DIRECT',
    0x6b: 'INVOKE_STATIC', 0x6c: 'INVOKE_INTERFACE',
    0x6d: 'RETURN_VOID_BARRIER', 0x6e: 'INVOKE_VIRTUAL_RANGE',
    0x6f: 'INVOKE_SUPER_RANGE', 0x70: 'INVOKE_DIRECT_RANGE',
    0x71: 'INVOKE_STATIC_RANGE', 0x72: 'INVOKE_INTERFACE_RANGE',
    0x73: 'NEG_INT', 0x74: 'NOT_INT', 0x75: 'NEG_LONG', 0x76: 'NOT_LONG',
    0x77: 'NEG_FLOAT', 0x78: 'NEG_DOUBLE', 0x79: 'INT_TO_LONG',
    0x7a: 'INT_TO_FLOAT', 0x7b: 'INT_TO_DOUBLE', 0x7c: 'LONG_TO_INT',
    0x7d: 'LONG_TO_FLOAT', 0x7e: 'LONG_TO_DOUBLE', 0x7f: 'FLOAT_TO_INT',
    0x80: 'FLOAT_TO_LONG', 0x81: 'FLOAT_TO_DOUBLE', 0x82: 'DOUBLE_TO_INT',
    0x83: 'DOUBLE_TO_LONG', 0x84: 'DOUBLE_TO_FLOAT', 0x85: 'INT_TO_BYTE',
    0x86: 'INT_TO_CHAR', 0x87: 'INT_TO_SHORT',
    0x90: 'ADD_INT', 0x91: 'SUB_INT', 0x92: 'MUL_INT', 0x93: 'DIV_INT',
    0x94: 'REM_INT', 0x95: 'AND_INT', 0x96: 'OR_INT', 0x97: 'XOR_INT',
    0x98: 'SHL_INT', 0x99: 'SHR_INT', 0x9a: 'USHR_INT',
    0x9b: 'ADD_LONG', 0x9c: 'SUB_LONG', 0x9d: 'MUL_LONG', 0x9e: 'DIV_LONG',
    0x9f: 'REM_LONG', 0xa0: 'AND_LONG', 0xa1: 'OR_LONG', 0xa2: 'XOR_LONG',
    0xa3: 'SHL_LONG', 0xa4: 'SHR_LONG', 0xa5: 'USHR_LONG',
    0xa6: 'ADD_FLOAT', 0xa7: 'SUB_FLOAT', 0xa8: 'MUL_FLOAT', 0xa9: 'DIV_FLOAT',
    0xaa: 'REM_FLOAT', 0xab: 'ADD_DOUBLE', 0xac: 'SUB_DOUBLE',
    0xad: 'MUL_DOUBLE', 0xae: 'DIV_DOUBLE', 0xaf: 'REM_DOUBLE',
    0xb0: 'ADD_INT_2ADDR', 0xb1: 'SUB_INT_2ADDR', 0xb2: 'MUL_INT_2ADDR',
    0xb3: 'DIV_INT_2ADDR', 0xb4: 'REM_INT_2ADDR', 0xb5: 'AND_INT_2ADDR',
    0xb6: 'OR_INT_2ADDR', 0xb7: 'XOR_INT_2ADDR', 0xb8: 'SHL_INT_2ADDR',
    0xb9: 'SHR_INT_2ADDR', 0xba: 'USHR_INT_2ADDR',
    0xbb: 'ADD_LONG_2ADDR', 0xbc: 'SUB_LONG_2ADDR', 0xbd: 'MUL_LONG_2ADDR',
    0xbe: 'DIV_LONG_2ADDR', 0xbf: 'REM_LONG_2ADDR', 0xc0: 'AND_LONG_2ADDR',
    0xc1: 'OR_LONG_2ADDR', 0xc2: 'XOR_LONG_2ADDR', 0xc3: 'SHL_LONG_2ADDR',
    0xc4: 'SHR_LONG_2ADDR', 0xc5: 'USHR_LONG_2ADDR',
    0xc6: 'ADD_FLOAT_2ADDR', 0xc7: 'SUB_FLOAT_2ADDR', 0xc8: 'MUL_FLOAT_2ADDR',
    0xc9: 'DIV_FLOAT_2ADDR', 0xca: 'REM_FLOAT_2ADDR',
    0xcb: 'ADD_DOUBLE_2ADDR', 0xcc: 'SUB_DOUBLE_2ADDR', 0xcd: 'MUL_DOUBLE_2ADDR',
    0xce: 'DIV_DOUBLE_2ADDR', 0xcf: 'REM_DOUBLE_2ADDR',
    0xd0: 'ADD_INT_LIT16', 0xd1: 'RSUB_INT_LIT16', 0xd2: 'MUL_INT_LIT16',
    0xd3: 'DIV_INT_LIT16', 0xd4: 'REM_INT_LIT16', 0xd5: 'AND_INT_LIT16',
    0xd6: 'OR_INT_LIT16', 0xd7: 'XOR_INT_LIT16',
    0xd8: 'ADD_INT_LIT8', 0xd9: 'RSUB_INT_LIT8', 0xda: 'MUL_INT_LIT8',
    0xdb: 'DIV_INT_LIT8', 0xdc: 'REM_INT_LIT8', 0xdd: 'AND_INT_LIT8',
    0xde: 'OR_INT_LIT8', 0xdf: 'XOR_INT_LIT8', 0xe0: 'SHL_INT_LIT8',
    0xe1: 'SHR_INT_LIT8', 0xe2: 'USHR_INT_LIT8',
    0xe3: 'INVOKE_POLYMORPHIC', 0xe4: 'INVOKE_POLYMORPHIC_RANGE',
    0xe5: 'INVOKE_CUSTOM', 0xe6: 'INVOKE_CUSTOM_RANGE',
    0xe7: 'CONST_METHOD_HANDLE', 0xe8: 'CONST_METHOD_TYPE',
}

DANGEROUS_METHODS = [
    'Runtime.exec', 'Runtime.getRuntime', 'ProcessBuilder', 'ProcessBuilder.start',
    'File.createTempFile', 'File.delete', 'FileOutputStream', 'FileInputStream',
    'Runtime.load', 'Runtime.loadLibrary', 'System.load', 'System.loadLibrary',
    'java.lang.Runtime.exec', 'java.lang.ProcessBuilder',
    'java.io.File.createTempFile', 'java.io.FileOutputStream',
    'java.lang.reflect.Method.invoke', 'java.lang.reflect.Constructor.newInstance',
    'dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader',
    'android.webkit.WebView.loadUrl', 'android.webkit.WebView.addJavascriptInterface',
    'android.app.Activity.startActivity', 'android.content.Intent',
]

class DEXParser:
    def __init__(self, path):
        self.path = path
        self.dex_data = None
        self.strings = []
        self.types = []
        self.protos = []
        self.fields = []
        self.methods = []
        self.classes = []
        self.method_code = {}
        self.class_data = {}
        self.static_fields = []
        self.instance_fields = []
        self.direct_methods = []
        self.virtual_methods = []

    def parse(self):
        with open(self.path, 'rb') as f:
            self.dex_data = f.read()
        data = self.dex_data
        if data[:4] != b'dex\n':
            raise ValueError(f"Not a valid DEX file: {self.path}")
        if len(data) < 112:
            raise ValueError("DEX file too small")

        self.string_ids_size = struct.unpack_from('<I', data, 56)[0]
        self.string_ids_off = struct.unpack_from('<I', data, 60)[0]
        self.type_ids_size = struct.unpack_from('<I', data, 64)[0]
        self.type_ids_off = struct.unpack_from('<I', data, 68)[0]
        self.proto_ids_size = struct.unpack_from('<I', data, 72)[0]
        self.proto_ids_off = struct.unpack_from('<I', data, 76)[0]
        self.field_ids_size = struct.unpack_from('<I', data, 80)[0]
        self.field_ids_off = struct.unpack_from('<I', data, 84)[0]
        self.method_ids_size = struct.unpack_from('<I', data, 88)[0]
        self.method_ids_off = struct.unpack_from('<I', data, 92)[0]
        self.class_defs_size = struct.unpack_from('<I', data, 96)[0]
        self.class_defs_off = struct.unpack_from('<I', data, 100)[0]
        self.data_size = struct.unpack_from('<I', data, 104)[0]
        self.data_off = struct.unpack_from('<I', data, 108)[0]

        self._parse_strings()
        self._parse_types()
        self._parse_protos()
        self._parse_fields()
        self._parse_methods()
        self._parse_classes()
        return self

    @staticmethod
    def _read_uleb128(data, offset):
        result = 0
        shift = 0
        pos = offset
        while pos < len(data):
            byte = data[pos]
            result |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
            if not (byte & 0x80):
                break
        return result, pos - offset

    def _parse_strings(self):
        data = self.dex_data
        off = self.string_ids_off
        for i in range(self.string_ids_size):
            str_off = struct.unpack_from('<I', data, off + i * 4)[0]
            if str_off >= len(data):
                self.strings.append('')
                continue
            try:
                length, consumed = self._read_uleb128(data, str_off)
                start = str_off + consumed
                if start + length > len(data):
                    self.strings.append('')
                    continue
                self.strings.append(data[start:start+length].decode('utf-8', errors='replace'))
            except:
                self.strings.append('')

    def _parse_types(self):
        data = self.dex_data
        off = self.type_ids_off
        for i in range(self.type_ids_size):
            idx = struct.unpack_from('<I', data, off + i * 4)[0]
            s = self.strings[idx] if idx < len(self.strings) else ''
            self.types.append(s)

    def _parse_protos(self):
        data = self.dex_data
        off = self.proto_ids_off
        for i in range(self.proto_ids_size):
            shorty_idx = struct.unpack_from('<I', data, off + i * 12)[0]
            ret_type_idx = struct.unpack_from('<I', data, off + i * 12 + 4)[0]
            param_idx = struct.unpack_from('<I', data, off + i * 12 + 8)[0]
            self.protos.append({
                'shorty': self.strings[shorty_idx] if shorty_idx < len(self.strings) else '',
                'return_type': self.types[ret_type_idx] if ret_type_idx < len(self.types) else '',
                'params_off': param_idx,
            })

    def _parse_fields(self):
        data = self.dex_data
        off = self.field_ids_off
        for i in range(self.field_ids_size):
            class_idx = struct.unpack_from('<H', data, off + i * 8)[0]
            type_idx = struct.unpack_from('<H', data, off + i * 8 + 2)[0]
            name_idx = struct.unpack_from('<I', data, off + i * 8 + 4)[0]
            self.fields.append({
                'class': self.types[class_idx] if class_idx < len(self.types) else '',
                'type': self.types[type_idx] if type_idx < len(self.types) else '',
                'name': self.strings[name_idx] if name_idx < len(self.strings) else '',
            })

    def _parse_methods(self):
        data = self.dex_data
        off = self.method_ids_off
        for i in range(self.method_ids_size):
            class_idx = struct.unpack_from('<H', data, off + i * 8)[0]
            proto_idx = struct.unpack_from('<H', data, off + i * 8 + 2)[0]
            name_idx = struct.unpack_from('<I', data, off + i * 8 + 4)[0]
            proto = self.protos[proto_idx] if proto_idx < len(self.protos) else {}
            self.methods.append({
                'class': self.types[class_idx] if class_idx < len(self.types) else '',
                'proto': proto,
                'return_type': proto.get('return_type', '') if proto else '',
                'proto_idx': proto_idx,
                'name': self.strings[name_idx] if name_idx < len(self.strings) else '',
            })

    def _parse_classes(self):
        data = self.dex_data
        off = self.class_defs_off
        for i in range(self.class_defs_size):
            class_idx = struct.unpack_from('<I', data, off + i * 32)[0]
            access_flags = struct.unpack_from('<I', data, off + i * 32 + 4)[0]
            superclass_idx = struct.unpack_from('<I', data, off + i * 32 + 8)[0]
            interfaces_off = struct.unpack_from('<I', data, off + i * 32 + 12)[0]
            source_file_idx = struct.unpack_from('<I', data, off + i * 32 + 16)[0]
            annotations_off = struct.unpack_from('<I', data, off + i * 32 + 20)[0]
            class_data_off = struct.unpack_from('<I', data, off + i * 32 + 24)[0]
            static_values_off = struct.unpack_from('<I', data, off + i * 32 + 28)[0]
            name = self.types[class_idx] if class_idx < len(self.types) else ''
            superclass = self.types[superclass_idx] if superclass_idx < len(self.types) else ''
            self.classes.append({
                'name': name,
                'access_flags': access_flags,
                'superclass': superclass,
                'class_data_off': class_data_off,
                'interfaces_off': interfaces_off,
                'source_file_idx': source_file_idx,
                'annotations_off': annotations_off,
                'static_values_off': static_values_off,
            })
            if class_data_off > 0:
                self._parse_class_data(class_data_off, name)

    def _parse_class_data(self, class_data_off, class_name):
        data = self.dex_data
        if class_data_off >= len(data):
            return
        try:
            static_fields_size = struct.unpack_from('<ULEB128', data, class_data_off)
            pos = class_data_off + len(static_fields_size[0])
        except:
            pos = class_data_off + 1
            static_fields_size = (0,)
        self.static_fields.append({'class': class_name, 'count': static_fields_size[0]})

    def get_class(self, name):
        for cls in self.classes:
            if name in cls['name']:
                return cls
        return None

    def get_methods_for_class(self, class_name):
        return [m for m in self.methods if class_name in m['class']]

    def get_fields_for_class(self, class_name):
        return [f for f in self.fields if class_name in f['class']]

    def disassemble_method(self, method):
        return {"name": method['name'], "instructions": []}

    def find_string(self, pattern):
        return [s for s in self.strings if pattern in s]

    def find_method(self, pattern):
        return [m for m in self.methods if pattern in m['name'] or pattern in m['class']]
