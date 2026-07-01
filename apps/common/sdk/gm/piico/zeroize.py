from ctypes import addressof, memset, sizeof


def zeroize_mutable_buffer(buffer, fill=0x00):
    if buffer is None:
        return 0

    fill = _normalize_fill(fill)
    if isinstance(buffer, bytearray):
        length = len(buffer)
        buffer[:] = bytes([fill]) * length
        return length

    view = memoryview(buffer)
    if view.readonly:
        return 0
    if view.format not in ("B", "b"):
        view = view.cast("B")
    length = view.nbytes
    view[:] = bytes([fill]) * length
    return length


def zeroize_ctypes_buffer(buffer, fill=0x00):
    if buffer is None:
        return 0

    length = sizeof(buffer)
    if length:
        memset(addressof(buffer), _normalize_fill(fill), length)
    return length


def _normalize_fill(fill):
    if not isinstance(fill, int):
        raise TypeError("zeroize fill must be an integer")
    if fill < 0 or fill > 0xFF:
        raise ValueError("zeroize fill must be between 0x00 and 0xFF")
    return fill
