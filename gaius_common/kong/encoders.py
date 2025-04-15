import json, codecs

class UnicodeEscapeEncoder(json.JSONEncoder):
    def encode(self, o):
        return codecs.decode(.dumps(o, ensure_ascii = False), 'unicode-escape')
