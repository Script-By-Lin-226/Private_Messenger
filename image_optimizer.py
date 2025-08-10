import os
import io
from PIL import Image, ImageOps
from typing import Tuple, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ImageOptimizer:
    """Optimizes images for faster uploads and better performance"""
    
    # Maximum dimensions for different image types
    MAX_DIMENSIONS = {
        'thumbnail': (150, 150),
        'preview': (300, 300),
        'full': (800, 800),
        'original': (1920, 1920)
    }
    
    # Quality settings for JPEG compression
    JPEG_QUALITY = 85
    JPEG_OPTIMIZE = True
    
    # PNG optimization
    PNG_OPTIMIZE = True
    
    @staticmethod
    def optimize_image(file_stream, filename: str, max_size: str = 'full') -> Tuple[bytes, str, int]:
        """
        Optimize an image file for faster uploads
        
        Args:
            file_stream: File stream or bytes
            filename: Original filename
            max_size: Maximum size category ('thumbnail', 'preview', 'full', 'original')
            
        Returns:
            Tuple of (optimized_bytes, new_filename, file_size)
        """
        try:
            # Open image
            if isinstance(file_stream, bytes):
                img = Image.open(io.BytesIO(file_stream))
            else:
                img = Image.open(file_stream)
            
            # Convert to RGB if necessary (for JPEG compatibility)
            if img.mode in ('RGBA', 'LA', 'P'):
                # Create white background for transparent images
                background = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'P':
                    img = img.convert('RGBA')
                background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                img = background
            elif img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get target dimensions
            target_width, target_height = ImageOptimizer.MAX_DIMENSIONS.get(max_size, (800, 800))
            
            # Calculate new dimensions maintaining aspect ratio
            img_width, img_height = img.size
            if img_width > target_width or img_height > target_height:
                img = ImageOps.fit(img, (target_width, target_height), method=Image.Resampling.LANCZOS)
            
            # Determine output format and optimize
            file_ext = os.path.splitext(filename)[1].lower()
            output_format = 'JPEG' if file_ext in ['.jpg', '.jpeg'] else 'PNG'
            
            # Optimize and save to bytes
            output_buffer = io.BytesIO()
            
            if output_format == 'JPEG':
                img.save(
                    output_buffer, 
                    format='JPEG', 
                    quality=ImageOptimizer.JPEG_QUALITY,
                    optimize=ImageOptimizer.JPEG_OPTIMIZE,
                    progressive=True
                )
            else:
                img.save(
                    output_buffer, 
                    format='PNG',
                    optimize=ImageOptimizer.PNG_OPTIMIZE
                )
            
            # Get optimized data
            optimized_bytes = output_buffer.getvalue()
            file_size = len(optimized_bytes)
            
            # Generate new filename with size indicator
            name_without_ext = os.path.splitext(filename)[0]
            new_filename = f"{name_without_ext}_{max_size}{file_ext}"
            
            logger.info(f"Image optimized: {filename} -> {new_filename} ({file_size} bytes)")
            
            return optimized_bytes, new_filename, file_size
            
        except Exception as e:
            logger.error(f"Error optimizing image {filename}: {str(e)}")
            # Return original file if optimization fails
            if isinstance(file_stream, bytes):
                return file_stream, filename, len(file_stream)
            else:
                file_stream.seek(0)
                return file_stream.read(), filename, file_stream.tell()
    
    @staticmethod
    def create_thumbnail(file_stream, filename: str) -> Tuple[bytes, str, int]:
        """Create a small thumbnail for faster preview loading"""
        return ImageOptimizer.optimize_image(file_stream, filename, 'thumbnail')
    
    @staticmethod
    def get_image_info(file_stream) -> dict:
        """Get basic image information without loading the entire image"""
        try:
            if isinstance(file_stream, bytes):
                img = Image.open(io.BytesIO(file_stream))
            else:
                img = Image.open(file_stream)
                file_stream.seek(0)  # Reset position
            
            return {
                'width': img.size[0],
                'height': img.size[1],
                'mode': img.mode,
                'format': img.format
            }
        except Exception as e:
            logger.error(f"Error getting image info: {str(e)}")
            return {}
    
    @staticmethod
    def should_optimize(filename: str, file_size: int) -> bool:
        """Determine if an image should be optimized based on size and type"""
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Always optimize large files
        if file_size > 1024 * 1024:  # > 1MB
            return True
        
        # Optimize common image formats
        if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
            return True
        
        return False
