import json, codecs

class UnicodeEscapeEncoder(json.JSONEncoder):
    def encode(self, o):
        return codecs.decode(json.dumps(o, ensure_ascii = False), 'unicode-escape')
