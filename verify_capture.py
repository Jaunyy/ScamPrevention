"""
Step 0: verify that screen recording permission is granted and mss returns a
non-blank frame before running the full detector.
"""
import sys
import statistics

try:
    import mss
    from PIL import Image
except ImportError:
    print("ERROR: missing packages. Run:  pip3 install mss Pillow")
    sys.exit(1)


def check_capture() -> None:
    with mss.mss() as sct:
        monitors = sct.monitors
        print(f"Detected {len(monitors) - 1} monitor(s).")

        # monitors[0] is the virtual "all screens" bounding box; monitors[1] is primary
        region = monitors[1]
        print(f"Primary monitor: {region['width']}x{region['height']} at ({region['left']}, {region['top']})")

        raw = sct.grab(region)
        img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")

    pixel_values = list(img.getdata())
    channels = [v for px in pixel_values for v in px]
    mean_brightness = statistics.mean(channels)
    unique_colors = len(set(pixel_values))

    print(f"Captured {img.width}x{img.height} image.")
    print(f"Mean pixel brightness : {mean_brightness:.1f} / 255")
    print(f"Unique colors sampled : {unique_colors}")

    if mean_brightness < 5:
        print("\nFAIL: image is nearly all black.")
        print("Did you grant Screen Recording permission and relaunch the terminal?")
        print("  System Settings → Privacy & Security → Screen Recording")
        sys.exit(1)

    if unique_colors < 100:
        print("\nFAIL: too few unique colors — capture may be blocked or showing a solid frame.")
        sys.exit(1)

    print("\nOK: screen capture is working.")
    img.save("/tmp/scam_detector_verify.png")
    print("Preview saved to /tmp/scam_detector_verify.png — open it to confirm it looks right.")


if __name__ == "__main__":
    check_capture()
