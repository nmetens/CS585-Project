from .helpers import _u32_to_le_bytes, _le_bytes_to_u32
from .rounds import _doubleround
from .constants import SIGMA

def _initial_state_256(key32: bytes, nonce8: bytes, counter64: int) -> list[int]:
    """
    Build the 4x4 Salsa20 state (row-major) for a 32-byte key and 8-byte nonce.
    Layout (32-bit LE words):
      0: c0   1..4: key[0..15]   5: c1
      6..7: nonce                8..9: counter
     10: c2  11..14: key[16..31] 15: c3
    """
    if len(key32) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce8) != 8:
        raise ValueError("nonce must be 8 bytes")

    c = _SIGMA
    k0, k1 = key32[:16], key32[16:]

    return [
        _le_bytes_to_u32(c[0:4]),
        _le_bytes_to_u32(k0[0:4]),
        _le_bytes_to_u32(k0[4:8]),
        _le_bytes_to_u32(k0[8:12]),
        _le_bytes_to_u32(k0[12:16]),
        _le_bytes_to_u32(c[4:8]),
        _le_bytes_to_u32(nonce8[0:4]),
        _le_bytes_to_u32(nonce8[4:8]),
        counter64 & 0xffffffff,
        (counter64 >> 32) & 0xffffffff,
        _le_bytes_to_u32(c[8:12]),
        _le_bytes_to_u32(k1[0:4]),
        _le_bytes_to_u32(k1[4:8]),
        _le_bytes_to_u32(k1[8:12]),
        _le_bytes_to_u32(k1[12:16]),
        _le_bytes_to_u32(c[12:16]),
    ]

# --- 3) One keystream block (64 bytes) ---
def salsa20_block(key32: bytes, nonce8: bytes, counter64: int) -> bytes:
    state = _initial_state_256(key32, nonce8, counter64)
    return _salsa20_hash(state)


