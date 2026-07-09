from .base import BinaryLoader


class GenericLoader(BinaryLoader):
    name = "generic"

    @classmethod
    def check(cls, data):
        return True

    @classmethod
    def load(cls, data, engine):
        loader = cls()
        loader.data = data
        loader.engine = engine
        loader.strings = set()
        loader.chunks = []
        chunk_size = 4096
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            loader.chunks.append({
                "offset": i,
                "size": len(chunk),
                "data": chunk
            })
            loader._extract_strings(chunk)
        engine.loader = loader
        return loader

    def _extract_strings(self, blob):
        current = []
        for byte in blob:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    self.strings.add("".join(current))
                current = []
