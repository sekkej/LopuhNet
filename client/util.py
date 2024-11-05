import xxhash
import random
import numpy as np
from PIL import Image
import colorsys
import pillow_avif
import math

def __random_color():
    hlscolor = [
        random.randint(0, 360)/360,
        random.randint(25, 75)/100,
        random.randint(75, 100)/100,
    ]
    converted = colorsys.hls_to_rgb(*hlscolor)
    color = tuple([int(cc*255) for cc in converted] + [255])
    return color

def __generate_avatar_mask(color: tuple[int, int, int]):
    mask = random.choices([0, 1], k=16)
    mask = np.array(mask).reshape((4, 4))
    mask = np.kron(mask, np.ones((64, 64))) # Expand mask
    mask_img = Image.fromarray((mask * 255).astype(np.uint8), 'L')

    color_layer = Image.new('RGBA', (256, 256), color)
    return color_layer, mask_img

def generate_avatar(seed: int):
    """Seed - a number up to 10 billions"""
    random.seed(seed)

    img = Image.new('RGBA', (512, 512), color=(255, 255, 255, 255))

    # # Deprecated
    # symmetry = i % 2 # 0 - horizontally symmetrical; 1 - vertically symmetrical
    # print(symmetry)

    # color = __saturate_color(random.choices(range(256), k=3))
    color = __random_color()
    cl1, mask1 = __generate_avatar_mask(color)
    cl2, mask2 = __generate_avatar_mask(color)
    
    mask1copy = mask1.copy().transpose(Image.FLIP_LEFT_RIGHT)
    mask2copy = mask2.copy().transpose(Image.FLIP_LEFT_RIGHT)
    img.paste(cl1, (0, 0), mask1)
    img.paste(cl1, (256, 0), mask1copy)
    img.paste(cl2, (0, 256), mask2)
    img.paste(cl2, (256, 256), mask2copy)

    return img

def get_avatar_seed(seed: str) -> int:
    return xxhash.xxh128(seed).intdigest() % (10 ** 10)

def __compress_to_avif(img, output_path, quality=50, speed=8):
    """
    Compress image to AVIF format
    quality: 0-100 (higher is better quality but larger file)
    speed: 0-10 (higher is faster but potentially lower compression)
    """
    if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
        img = img.convert('RGBA')
    else:
        img = img.convert('RGB')
    
    img.save(
        output_path,
        format='AVIF',
        quality=quality,
        speed=speed
    )

def compress_image(input_path, output_path):
    img = Image.open(input_path)
    quality = round(-100 * math.sin((sum(img.size) * 3.14159 - 1555) / 20354) + 100)
    __compress_to_avif(img, output_path, max(min(quality, 100), 25))