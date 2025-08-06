#!/usr/bin/env python3
"""
Generate app icons for mobile homescreen installation
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, text="PM", bg_color="#16213e", text_color="#ffffff"):
    """Create a simple icon with text"""
    # Create a new image with the specified size
    img = Image.new('RGBA', (size, size), bg_color)
    draw = ImageDraw.Draw(img)
    
    # Calculate font size (approximately 60% of icon size)
    font_size = int(size * 0.6)
    
    try:
        # Try to use a system font
        font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", font_size)
    except:
        try:
            # Fallback to another common font
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
        except:
            # Use default font
            font = ImageFont.load_default()
    
    # Calculate text position to center it
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (size - text_width) // 2
    y = (size - text_height) // 2
    
    # Draw the text
    draw.text((x, y), text, fill=text_color, font=font)
    
    return img

def create_chat_icon(size, bg_color="#4CAF50", text_color="#ffffff"):
    """Create a chat icon"""
    img = Image.new('RGBA', (size, size), bg_color)
    draw = ImageDraw.Draw(img)
    
    # Draw a simple chat bubble
    margin = size // 8
    bubble_width = size - 2 * margin
    bubble_height = size - 2 * margin
    
    # Main bubble
    draw.rounded_rectangle(
        [margin, margin, margin + bubble_width, margin + bubble_height],
        radius=size // 6,
        fill="#ffffff",
        outline=text_color,
        width=2
    )
    
    # Chat dots
    dot_size = size // 12
    dot_spacing = size // 8
    start_x = margin + size // 4
    start_y = margin + size // 3
    
    for i in range(3):
        x = start_x + i * dot_spacing
        y = start_y
        draw.ellipse([x, y, x + dot_size, y + dot_size], fill="#666666")
    
    return img

def create_admin_icon(size, bg_color="#FF5722", text_color="#ffffff"):
    """Create an admin icon"""
    img = Image.new('RGBA', (size, size), bg_color)
    draw = ImageDraw.Draw(img)
    
    # Draw a shield-like shape for admin
    margin = size // 8
    shield_width = size - 2 * margin
    shield_height = size - 2 * margin
    
    # Shield points
    points = [
        (margin + shield_width // 2, margin),  # Top
        (margin + shield_width, margin + shield_height // 3),  # Right top
        (margin + shield_width * 3 // 4, margin + shield_height),  # Right bottom
        (margin + shield_width // 2, margin + shield_height * 4 // 5),  # Bottom
        (margin + shield_width // 4, margin + shield_height),  # Left bottom
        (margin, margin + shield_height // 3),  # Left top
    ]
    
    draw.polygon(points, fill="#ffffff", outline=text_color, width=2)
    
    # Draw "A" in the center
    font_size = int(size * 0.4)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", font_size)
    except:
        font = ImageFont.load_default()
    
    bbox = draw.textbbox((0, 0), "A", font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (size - text_width) // 2
    y = (size - text_height) // 2
    
    draw.text((x, y), "A", fill=bg_color, font=font)
    
    return img

def generate_all_icons():
    """Generate all required icons"""
    print("🎨 Generating app icons for mobile homescreen...")
    
    # Create icons directory
    icons_dir = "static/icons"
    os.makedirs(icons_dir, exist_ok=True)
    
    # Icon sizes for different devices
    sizes = [72, 96, 128, 144, 152, 192, 384, 512]
    
    # Generate main app icons
    print("📱 Generating main app icons...")
    for size in sizes:
        icon = create_icon(size)
        filename = f"{icons_dir}/icon-{size}x{size}.png"
        icon.save(filename, "PNG")
        print(f"✅ Created {filename}")
    
    # Generate chat shortcut icon
    print("\n💬 Generating chat shortcut icon...")
    chat_icon = create_chat_icon(96)
    chat_filename = f"{icons_dir}/chat-icon-96x96.png"
    chat_icon.save(chat_filename, "PNG")
    print(f"✅ Created {chat_filename}")
    
    # Generate admin shortcut icon
    print("\n👑 Generating admin shortcut icon...")
    admin_icon = create_admin_icon(96)
    admin_filename = f"{icons_dir}/admin-icon-96x96.png"
    admin_icon.save(admin_filename, "PNG")
    print(f"✅ Created {admin_filename}")
    
    # Create screenshots directory (placeholder)
    screenshots_dir = "static/screenshots"
    os.makedirs(screenshots_dir, exist_ok=True)
    
    # Create placeholder screenshots
    print("\n📸 Creating placeholder screenshots...")
    
    # Chat screen placeholder
    chat_screenshot = Image.new('RGBA', (1280, 720), "#1a1a2e")
    draw = ImageDraw.Draw(chat_screenshot)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 48)
    except:
        font = ImageFont.load_default()
    
    draw.text((640, 360), "Chat Interface", fill="#ffffff", font=font, anchor="mm")
    chat_screenshot.save(f"{screenshots_dir}/chat-screen.png", "PNG")
    print(f"✅ Created {screenshots_dir}/chat-screen.png")
    
    # Admin screen placeholder
    admin_screenshot = Image.new('RGBA', (1280, 720), "#16213e")
    draw = ImageDraw.Draw(admin_screenshot)
    draw.text((640, 360), "Admin Dashboard", fill="#ffffff", font=font, anchor="mm")
    admin_screenshot.save(f"{screenshots_dir}/admin-screen.png", "PNG")
    print(f"✅ Created {screenshots_dir}/admin-screen.png")
    
    print("\n🎉 All icons generated successfully!")
    print("📱 Your app is now ready for mobile homescreen installation!")

if __name__ == "__main__":
    generate_all_icons() 