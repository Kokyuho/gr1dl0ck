def xor_buffers(buf1: bytes, buf2: bytes) -> bytes:
    """
    XORs two equal-length byte buffers and returns the resulting byte buffer.

    Args:
        buf1 (bytes): The first buffer.
        buf2 (bytes): The second buffer.

    Returns:
        bytes: A new bytes object resulting from XOR-ing buf1 and buf2.

    Raises:
        ValueError: If the two buffers are not of equal length.
    """
    if len(buf1) != len(buf2):
        raise ValueError("Both buffers must have equal length.")
    
    return bytes(b1 ^ b2 for b1, b2 in zip(buf1, buf2))


if __name__ == "__main__":
    buf1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    buf2 = bytes.fromhex("686974207468652062756c6c277320657965")
    result = xor_buffers(buf1, buf2)
    assert result == bytes.fromhex("746865206b696420646f6e277420706c6179")
    print("success!")
