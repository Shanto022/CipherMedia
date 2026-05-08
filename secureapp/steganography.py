from PIL import Image
import io
import numpy as np

DELIMITER = "|||END|||"


def hide_message(image_bytes, message):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    width, height = img.size

    full_message = message + DELIMITER
    binary = ''.join(format(ord(c), '08b') for c in full_message)
    n_bits = len(binary)

    if n_bits > width * height * 3:
        raise ValueError("Message too long for this image.")

    # Use numpy for fast pixel operations
    pixels = np.array(img, dtype=np.uint8)
    flat   = pixels.flatten()

    bits_array = np.array([int(b) for b in binary], dtype=np.uint8)

    # Set LSB of first n_bits pixels
    flat[:n_bits] = (flat[:n_bits] & 0xFE) | bits_array

    new_pixels = flat.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels, "RGB")

    output = io.BytesIO()
    new_img.save(output, format="PNG")
    return output.getvalue()


def extract_message(image_bytes):
    img    = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat   = pixels.flatten()

    # Extract all LSBs at once
    bits = (flat & 1).tolist()

    chars = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        chars += chr(int(''.join(str(b) for b in byte), 2))
        if chars.endswith(DELIMITER):
            return chars[:-len(DELIMITER)]

    return ""