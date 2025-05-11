from PIL import Image
from PIL.ExifTags import TAGS

def extract_image_metadata(image_path):
    image = Image.open(image_path)
    exif_data = image._getexif()

    if exif_data is None:
        return {}

    metadata = {}
    for tag, value in exif_data.items():
        tag_name = TAGS.get(tag, tag)
        metadata[tag_name] = value

    return metadata

def extract_gps_location(exif_data):
    if "GPSInfo" not in exif_data:
        return None

    gps_info = exif_data["GPSInfo"]
    latitude = gps_info.get(2)
    longitude = gps_info.get(4)

    if latitude and longitude:
        lat = latitude[0] + (latitude[1] / 60.0) + (latitude[2] / 3600.0)
        lon = longitude[0] + (longitude[1] / 60.0) + (longitude[2] / 3600.0)
        return [lat, lon]

    return None
