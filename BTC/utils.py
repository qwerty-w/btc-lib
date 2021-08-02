from hashlib import sha256


def get_2sha256(bytes_: bytes) -> bytes:
    return sha256(sha256(bytes_).digest()).digest()
