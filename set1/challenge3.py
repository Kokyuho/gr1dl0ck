from typing import Tuple
from english_char_frequency_scores import FREQUENCY_SCORES


def score_text(text: bytes) -> float:
    score = 0
    for byte in text:
        char = chr(byte).upper()
        if char in FREQUENCY_SCORES:
            score += FREQUENCY_SCORES[char]

    return score


def single_byte_xor_cipher(hex_str: str) -> Tuple[int, bytes]:
    """
    Decrypts a hex-encoded string that has been XOR'd against a single byte.

    Returns:
        A tuple (key, decrypted_bytes) where:
         - key: the single-byte key (0-255) used for XOR.
         - decrypted_bytes: the resulting plaintext as bytes.
    """
    ciphertext = bytes.fromhex(hex_str)
    best_score = float("-inf")
    best_result = None
    best_key = None

    for key in range(256):
        plaintext_candidate = bytes(b ^ key for b in ciphertext)
        candidate_score = score_text(plaintext_candidate)
        if candidate_score > best_score:
            best_score = candidate_score
            best_result = plaintext_candidate
            best_key = key

    return best_key, best_result


if __name__ == "__main__":
    # The given hex-encoded ciphertext.
    hex_ciphertext = (
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )

    key, decrypted = single_byte_xor_cipher(hex_ciphertext)

    print("Key (as int):", key)
    print("Key (as char):", chr(key))
    print("Decrypted message:", decrypted.decode("utf-8"))
