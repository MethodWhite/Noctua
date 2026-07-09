class MWInstruction:
    def __init__(self, address, bytes_raw, mnemonic, op_str, obj=None):
        self.address = address
        self.bytes_raw = bytes_raw
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.obj = obj
        self.operands = self._parse_operands(op_str)

    def _parse_operands(self, op_str):
        if not op_str:
            return []
        return [op.strip() for op in op_str.split(",")]

    def __repr__(self):
        return f"MWInstruction(0x{self.address:x}: {self.mnemonic} {self.op_str})"


class MWBasicBlock:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.instructions = []
        self.successors = []
        self.predecessors = []

    def add_instruction(self, instr):
        self.instructions.append(instr)

    def add_successor(self, block):
        if block not in self.successors:
            self.successors.append(block)
            block.predecessors.append(self)

    def __repr__(self):
        return f"MWBasicBlock(0x{self.start:x}-0x{self.end:x}, {len(self.instructions)} insns)"


class MWFunction:
    def __init__(self, name, entry):
        self.name = name
        self.entry = entry
        self.basic_blocks = []
        self.instructions = []
        self.calls = []
        self.strings = []
        self.decompiled = None

    def add_basic_block(self, block):
        self.basic_blocks.append(block)
        self.instructions.extend(block.instructions)

    def add_call(self, target):
        if target not in self.calls:
            self.calls.append(target)

    def add_string(self, s):
        if s not in self.strings:
            self.strings.append(s)

    def __repr__(self):
        return f"MWFunction({self.name} @ 0x{self.entry:x}, {len(self.instructions)} insns)"
