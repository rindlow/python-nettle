import _nettle

class RSAKeyPair (_nettle.RSAKeyPair):
    def __init__(self, *args, **kwargs):
        _nettle.RSAKeyPair.__init__(self, *args, **kwargs)

class RSAPubKey (_nettle.RSAPubKey):
    def __init__(self, *args, **kwargs):
        _nettle.RSAPubKey.__init__(self, *args, **kwargs)
        
