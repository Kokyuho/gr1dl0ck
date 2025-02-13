import base64


def hex_to_base64(hex_string: str) -> str:
    """
    Converts a hex-encoded string to a Base64-encoded string.

    Args:
        hex_string (str): A string containing hexadecimal characters.

    Returns:
        str: The Base64-encoded representation of the input.
    """
    byte_data = bytes.fromhex(hex_string)
    base64_str = base64.b64encode(byte_data).decode("utf-8")

    return base64_str


if __name__ == "__main__":
    hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64_output = hex_to_base64(hex_input)
    assert (
        base64_output
        == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
    print("success!")
