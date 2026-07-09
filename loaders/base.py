class BinaryLoader:
    name = ""

    @classmethod
    def check(cls, data):
        return False

    @classmethod
    def load(cls, data, engine):
        raise NotImplementedError
