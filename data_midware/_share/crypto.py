from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    load_pem_private_key,
    NoEncryption
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP, PSS
from base64 import b64encode, b64decode

from pydantic_core import core_schema


class CryptoAES(object):
    def __init__(self, password: bytes = b'', salt: bytes = None) -> None:
        if salt is None:
            _kdf = ConcatKDFHash(
                algorithm=SHA256(),
                length=64,  # 输出48(32+16)字节也是循环2次
                otherinfo=None
            )
        else:
            _kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=64,
                salt=salt,
                iterations=654321
            )
        _keyiv = _kdf.derive(password)
        _key = _keyiv[-32:]  # AES最大支持32字节(AES256)
        _iv = _keyiv[:16]  # CBC模式需要和AES.block_size一致，即16字节
        self.cipher = Cipher(AES(_key), CBC(_iv))
        self.padding = PKCS7(AES.block_size)

    def encrypt(self, plainbytes: bytes) -> str:
        _encryptor = self.cipher.encryptor()
        _padder = self.padding.padder()
        _paddedbytes = _padder.update(plainbytes) + _padder.finalize()
        _cipherbytes = _encryptor.update(_paddedbytes) + _encryptor.finalize()
        return b64encode(_cipherbytes).decode()

    def decrypt(self, cipherb64: str) -> bytes:
        _decryptor = self.cipher.decryptor()
        _cipherbytes = b64decode(cipherb64)
        _padded_plainbytes = _decryptor.update(_cipherbytes) + _decryptor.finalize()
        _unpadder = self.padding.unpadder()
        return _unpadder.update(_padded_plainbytes) + _unpadder.finalize()

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        return core_schema.is_instance_schema(cls)


class CryptoRSA(object):
    def __init__(self, size: int = 2048) -> None:  # 比特，必须大于等于512（库限制）
        self.private_key = generate_private_key(public_exponent=65537, key_size=size)  # public_exponent固定为65537或3
        self.public_key = self.private_key.public_key()
        self.padding1 = OAEP(MGF1(algorithm=SHA256()), SHA256(), None)
        # OAEP（最优非对称加密填充算法）
        # MGF1（掩码生成函数1）的长度要不能小于填充算法的长度，不相同可能会有兼容性问题
        # OAEP下可加密的最大长度：keyLen(2048)/8 - 2*hashLen(256)/8 - 2 = 190字节
        self.padding2 = PSS(mgf=MGF1(algorithm=SHA256()), salt_length=32)
        # PSS盐的最大长度：keyLen(2048)/8 - hashLen(256)/8 - 2 = 222字节

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def private_pem(self) -> str:
        return self.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ).decode()

    def encrypt(self, plainbytes: bytes) -> str:
        _cipherbytes = self.public_key.encrypt(
            plainbytes,
            self.padding1
        )
        return b64encode(_cipherbytes).decode()

    def decrypt(self, cipherb64: str) -> bytes:
        _cipherbytes = b64decode(cipherb64)
        return self.private_key.decrypt(
            _cipherbytes,
            self.padding1
        )

    def load_private_key(self, path: str) -> None:
        with open(path, 'rb') as f:
            pem = f.read()
        self.private_key = load_pem_private_key(pem, password=None)
        self.public_key = self.private_key.public_key()

    def verify_signature(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                data,
                self.padding2,
                SHA256()
            )
            return True
        except Exception:
            return False
