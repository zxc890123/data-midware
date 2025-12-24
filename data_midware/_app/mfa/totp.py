from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from time import time
from typing import Generator


class Totp(object):
    def __init__(
        self,
        secret: bytes,
        algorithm: str = 'sha1',
        interval: int = 30,
        digits: int = 6,
        results: int = 10
    ) -> None:
        self.interval = interval
        self.results = results
        for hasher in (SHA1, SHA256, SHA512):
            if hasher.name.lower() == algorithm.lower():
                break
        self.totp = TOTP(secret, digits, hasher(), interval, enforce_key_length=False)

    def codes(self, time_: float = None) -> Generator[str, None, None]:
        if time_ is None:
            time_ = time()
        for step in range(self.results):
            yield self.totp.generate(time_ + step * self.interval).decode()
