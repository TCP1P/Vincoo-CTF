import os
from PIL import Image, ImageDraw, ImageFont
import random

def generate_challenge():
    # 1. Create a blank image
    width, height = 800, 600
    image = Image.new('RGB', (width, height), color='black') # Dark background
    draw = ImageDraw.Draw(image)

    # 2. Draw the flag
    # Try to load a font, fallback to default
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except IOError:
        font = ImageFont.load_default()

    text = "SnapanCTF{h34d3r5_4r3_cruc14l}"
    
    # Calculate text position to center it
    # getbbox returns (left, top, right, bottom)
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (width - text_width) / 2
    y = (height - text_height) / 2

    # Draw text with some "glitch" color
    draw.text((x, y), text, font=font, fill=(0, 255, 0)) # Green retro terminal style

    # Add some noise/lines to make it look "corrupted" visually
    for _ in range(50):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        color = (random.randint(0, 50), random.randint(0, 100), random.randint(0, 50))
        draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

    # 3. Save the original image temporarily
    dist_dir = os.path.join(os.path.dirname(__file__), '../dist')
    os.makedirs(dist_dir, exist_ok=True)
    temp_path = os.path.join(dist_dir, 'temp.png')
    final_path = os.path.join(dist_dir, 'memories.png')
    
    image.save(temp_path)

    # 4. Corrupt the Magic Bytes
    with open(temp_path, 'rb') as f:
        data = bytearray(f.read())

    # PNG Magic Bytes: 89 50 4E 47 0D 0A 1A 0A
    # Corrupt them
    garbage_header = b'\xDE\xAD\xBE\xEF\x00\x00\x00\x00'
    data[:8] = garbage_header

    with open(final_path, 'wb') as f:
        f.write(data)

    # Clean up
    os.remove(temp_path)
    print(f"Generated corrupted image at {final_path}")

if __name__ == "__main__":
    generate_challenge()
