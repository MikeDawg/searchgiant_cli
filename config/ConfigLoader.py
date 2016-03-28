import types

# I stole this concept from Flask :) 

class ConfigLoader(dict):
    def __init__(self, defaults=None):
        dict.__init__(self, defaults or {})

    def from_file(self, filename):
        d = types.ModuleType('config')
        d.__file__ = filename
        with open(filename) as config_file:
            exec(compile(config_file.read(), filename, 'exec'), d.__dict__)
        self.from_object(d)
        return True

    def from_object(self, obj):
        for key in dir(obj):
            if key.isupper():
                self[key] = getattr(obj, key)