from noctua.modules.base import AnalyzerModule

class CryptoModule(AnalyzerModule):
    name = "crypto"
    description = "Crypto constant scanner"
    applies_to = []

    def analyze(self):
        try:
            data = getattr(self.engine, 'data', b'')
            consts = []
            sigs = [('AES_SBOX_START', b'\x63\x7c\x77\x7b'), ('AES_RSBOX', b'\x52\x09\x6a\xd5'), ('BASE64', b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef')]
            for name, sig in sigs:
                if sig in data:
                    consts.append(f"{name} found")
            self.results = {'constants': consts}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

