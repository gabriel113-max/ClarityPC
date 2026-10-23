import math
from PIL import Image, ImageDraw, ImageFilter

def make_clarity_icon():
    canvas_size = 512
    img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Sleek Windows 11 Dark Squircle Tile
    margin = 32
    r = 100
    # Base dark surface
    draw.rounded_rectangle(
        [margin, margin, canvas_size - margin, canvas_size - margin],
        radius=r,
        fill=(18, 18, 22, 255),
        outline=(0, 240, 255, 90),
        width=4
    )

    # Inner radial cyan glow behind the icon
    glow = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    center_x, center_y = canvas_size // 2, canvas_size // 2
    gdraw.ellipse(
        [center_x - 140, center_y - 140, center_x + 140, center_y + 140],
        fill=(0, 240, 255, 40)
    )
    glow = glow.filter(ImageFilter.GaussianBlur(radius=50))
    img = Image.alpha_composite(img, glow)
    draw = ImageDraw.Draw(img)

    # Geometry for the 3 isometric blue squares (SVG: M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5)
    pad_x = 96
    pad_y = 96
    w = canvas_size - 2 * pad_x
    h = canvas_size - 2 * pad_y

    def pt(x, y):
        return (pad_x + (x / 24.0) * w, pad_y + (y / 24.0) * h)

    top_pts = [pt(12, 2.8), pt(2.8, 7.3), pt(12, 11.8), pt(21.2, 7.3)]
    mid_pts = [pt(2.8, 12.3), pt(12, 16.8), pt(21.2, 12.3)]
    bot_pts = [pt(2.8, 17.3), pt(12, 21.8), pt(21.2, 17.3)]

    stroke_w = 22

    # Draw bottom layer (Deep vibrant cyan-blue)
    draw.line(bot_pts, fill=(0, 160, 245, 255), width=stroke_w, joint="round")
    # Draw circle at end points for round caps
    for p in [bot_pts[0], bot_pts[-1]]:
        draw.ellipse([p[0] - stroke_w/2, p[1] - stroke_w/2, p[0] + stroke_w/2, p[1] + stroke_w/2], fill=(0, 160, 245, 255))

    # Draw middle layer (Electric cyan)
    draw.line(mid_pts, fill=(0, 205, 255, 255), width=stroke_w, joint="round")
    for p in [mid_pts[0], mid_pts[-1]]:
        draw.ellipse([p[0] - stroke_w/2, p[1] - stroke_w/2, p[0] + stroke_w/2, p[1] + stroke_w/2], fill=(0, 205, 255, 255))

    # Draw top layer (Luminous cyan with glassmorphic fill)
    draw.polygon(top_pts, fill=(0, 240, 255, 65), outline=(0, 245, 255, 255), width=stroke_w)
    for p in top_pts:
        draw.ellipse([p[0] - stroke_w/2, p[1] - stroke_w/2, p[0] + stroke_w/2, p[1] + stroke_w/2], fill=(0, 245, 255, 255))

    # Export multi-size Windows .ico
    ico_path = "C:/Users/gabri/ClarityPC/package/clarity.ico"
    ico_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save(ico_path, format="ICO", sizes=ico_sizes)
    print(f"Generated multi-size icon: {ico_path}")

    # Also save a 256x256 PNG for web or preview
    img.resize((256, 256), Image.Resampling.LANCZOS).save("C:/Users/gabri/ClarityPC/package/clarity_256.png")
    print("Saved 256x256 PNG preview")

if __name__ == "__main__":
    make_clarity_icon()
