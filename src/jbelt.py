
from py4j.java_gateway import JavaGateway

gateway = JavaGateway()

point = gateway.entry_point
signer = point.getSigner()
verificator = point.getVerificator()
keyManager = point.getKeyManager()


def calc_keys(bytes):
    return keyManager.calcKeyPair(bytearray(bytes))


def sign(xml, keys=keyManager.generateKeyPair()):
    return point.getBXS().sign(xml, keys)


def genKeys(length=128):
    keyManager.initialize(length)
    keys = keyManager.generateKeyPair()
    return {
        'priv': keys.getPrivate().getBytes(),
        'pub': keys.getPublic().getBytes()
    }


def verify(xml):
    return point.getBXS().verify(xml)


def enc(xml, pubKeyBytes):
    return point.getBXS().enc(xml, bytearray(str(pubKeyBytes)))


def dec(xml, privKeyBytes):
    return point.getBXS().dec(xml, bytearray(str(privKeyBytes)))
