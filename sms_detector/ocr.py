from PIL import Image, ImageEnhance, ImageFilter
import pytesseract

from .config import TESSERACT_CMD

pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD


def preprocess_image(image: Image.Image) -> Image.Image:
    """Enhance image for better OCR accuracy."""
    image = image.convert("L")
    image = image.filter(ImageFilter.SHARPEN)
    image = ImageEnhance.Contrast(image).enhance(2.0)
    return image


def extract_text(image: Image.Image) -> str:
    """Run Tesseract OCR on the image."""
    processed = preprocess_image(image)
    text = pytesseract.image_to_string(processed, config="--psm 6")
    return text.strip()
