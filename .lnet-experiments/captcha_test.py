# from PIL import Image
# from captcha.image import ImageCaptcha

# image = ImageCaptcha(width=192, font_sizes=tuple(range(36, 48)))
# data = image.generate('8 * three = ?')
# Image.open(data).show()

from multicolorcaptcha import CaptchaGenerator

# Captcha image size number (2 -> 640x360)
CAPCTHA_SIZE_NUM = 4

# Create Captcha Generator object of specified size
generator = CaptchaGenerator(CAPCTHA_SIZE_NUM)

# Generate a captcha image
captcha = generator.gen_captcha_image(difficult_level=2)
math_captcha = generator.gen_math_captcha_image(difficult_level=2)

# Get information of standard captcha
image = captcha.image
characters = captcha.characters

# Get information of math captcha
# math_image = math_captcha.image
# math_equation_string = math_captcha.equation_str
# math_equation_result = math_captcha.equation_result

# Save the images to files
image.show()
# math_image.show()