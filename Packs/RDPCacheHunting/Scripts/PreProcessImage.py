import cv2
import numpy as np
from PIL import Image
import io
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# grey scale
def get_grayscale(image):
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)


# sharpened
def sharpened(image):
    kernel = np.array([[-1, -1, -1], [-1, 8, -1], [-1, -1, 0]], np.float32)
    kernel = 1 / 3 * kernel
    sharp = cv2.filter2D(image, -1, kernel)
    return sharp


def image_resize_big(image):
    size = 7016, 4961
    image = image.resize(size, Image.ANTIALIAS)
    #image = image.resize((8192, 6656), PIL.Image.NEAREST)
    return image


def image_resize_small(image):
    size = 1680, 1050
    image = image.resize(size, Image.ANTIALIAS)
    #image = image.resize((8192, 6656), PIL.Image.NEAREST)
    return image


def main():
    stream_gray = io.BytesIO()
    stream_sharp = io.BytesIO()
    stream_orig = io.BytesIO()
    args = demisto.args()
    entry_id = args.get('entryID')
    result = demisto.getFilePath(entry_id)
    if not result:
        return_error("Couldn't find entry id: {}".format(entry_id))
    file_path = result['path']
    img = cv2.imread(file_path)
    # Generate grayscale image
    grayscale_image = get_grayscale(img)
    final_grayscale_image = Image.fromarray(grayscale_image)
    resized_grayscale_image = image_resize_big(final_grayscale_image)
    resized_grayscale_image.save(stream_gray, format="png")
    stream_gray.seek(0)
    # Generate sharpened image
    sharp_image = sharpened(img)
    final_sharp_image = Image.fromarray(sharp_image)
    resized_sharp_image = image_resize_big(final_sharp_image)
    resized_sharp_image.save(stream_sharp, format="png")
    stream_sharp.seek(0)
    # Generate original image
    final_orig_image = Image.fromarray(img)
    resized_orig_image = image_resize_small(final_orig_image)
    resized_orig_image.save(stream_orig, format="jpeg")
    stream_orig.seek(0)
    # Return files
    return_results(fileResult('final_gray.png', stream_gray.read()))
    return_results(fileResult('final_sharp.png', stream_sharp.read()))
    return_results(fileResult('final_orig.jpeg', stream_orig.read()))


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
