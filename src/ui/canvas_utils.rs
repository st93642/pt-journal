use gtk4::prelude::*;
use gtk4::{gdk};

/// Canvas item representing an image on the canvas
#[derive(Clone)]
#[allow(dead_code)]
pub struct CanvasItem {
    pub texture: gdk::Texture,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub selected: bool,
    pub picture_widget: Option<gtk4::Picture>,
    pub path: Option<String>,
}

/// Check if a file path has a valid image extension
pub fn is_valid_image_extension(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        matches!(ext_str.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "webp")
    } else {
        false
    }
}

/// Validate that a file exists and is readable
pub fn validate_image_file(path: &std::path::Path) -> Result<(), String> {
    if !path.exists() {
        return Err("File does not exist".to_string());
    }

    if !path.is_file() {
        return Err("Path is not a file".to_string());
    }

    match std::fs::metadata(path) {
        Ok(metadata) => {
            if metadata.len() == 0 {
                return Err("File is empty".to_string());
            }
            Ok(())
        }
        Err(e) => Err(format!("Cannot read file metadata: {}", e)),
    }
}

/// Attempt to create a texture from a file path
pub fn create_texture_from_file(path: &std::path::Path) -> Result<gdk::Texture, String> {
    validate_image_file(path)?;

    match gdk::Texture::from_filename(path) {
        Ok(texture) => Ok(texture),
        Err(e) => Err(format!("Failed to create texture from file: {}", e)),
    }
}

/// Create a canvas item from a texture
pub fn create_canvas_item(texture: gdk::Texture, x: f64, y: f64, path: Option<String>) -> CanvasItem {
    let width = texture.width() as f64;
    let height = texture.height() as f64;
    CanvasItem {
        texture,
        x,
        y,
        width,
        height,
        selected: false,
        picture_widget: None,
        path,
    }
}