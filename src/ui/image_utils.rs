use gtk4::prelude::*;
use gtk4::{gdk};
use std::path::Path;
use chrono;

/// Check if a file path has a valid image extension
#[allow(dead_code)]
pub fn is_valid_image_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        matches!(ext_str.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "webp")
    } else {
        false
    }
}

/// Validate that a file exists and is readable
#[allow(dead_code)]
pub fn validate_image_file(path: &Path) -> Result<(), String> {
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
/// This is a wrapper around gdk::Texture::from_filename for testing
#[allow(dead_code)]
pub fn create_texture_from_file(path: &Path) -> Result<gdk::Texture, String> {
    validate_image_file(path)?;

    match gdk::Texture::from_filename(path) {
        Ok(texture) => Ok(texture),
        Err(e) => Err(format!("Failed to create texture from file: {}", e)),
    }
}

/// Attempt to create a texture from a pixbuf with error handling
/// This is a wrapper for testing purposes
pub fn create_texture_from_pixbuf(pixbuf: &gdk::gdk_pixbuf::Pixbuf) -> Result<gdk::Texture, String> {
    // Validate pixbuf dimensions
    if pixbuf.width() <= 0 || pixbuf.height() <= 0 {
        return Err(format!("Cannot create texture from pixbuf with invalid dimensions: {}x{}",
                          pixbuf.width(), pixbuf.height()));
    }
    Ok(gdk::Texture::for_pixbuf(pixbuf))
}

/// Attempt to create a pixbuf from a file path with proper error handling
#[allow(dead_code)]
pub fn create_pixbuf_from_file(path: &Path) -> Result<gdk::gdk_pixbuf::Pixbuf, String> {
    validate_image_file(path)?;

    match gdk::gdk_pixbuf::Pixbuf::from_file(path) {
        Ok(pixbuf) => Ok(pixbuf),
        Err(e) => Err(format!("Failed to create pixbuf from file: {}", e)),
    }
}

/// Insert a paintable (texture) into a text buffer at the end
#[allow(dead_code)]
pub fn insert_paintable_into_buffer(buffer: &gtk4::TextBuffer, paintable: &gdk::Texture) {
    buffer.begin_user_action();
    let mut iter = buffer.end_iter();
    buffer.insert_paintable(&mut iter, paintable);
    buffer.end_user_action();
}

/// Save a texture to a PNG file
#[allow(dead_code)]
pub fn save_texture_to_png(texture: &gdk::Texture, path: &std::path::Path) -> Result<(), String> {
    match texture.save_to_png(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to save texture to PNG: {}", e)),
    }
}

/// Save a pixbuf to a PNG file
#[allow(dead_code)]
pub fn save_pixbuf_to_png(pixbuf: &gdk::gdk_pixbuf::Pixbuf, path: &std::path::Path) -> Result<(), String> {
    match pixbuf.savev(path, "png", &[]) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to save pixbuf to PNG: {}", e)),
    }
}

/// Get the images directory for the current session
/// Images are stored in an 'evidence' folder next to the session file
#[allow(dead_code)]
pub fn get_session_images_dir(session_path: Option<&Path>) -> std::path::PathBuf {
    match session_path {
        Some(path) => {
            // Store images in 'evidence' subfolder next to the session.json file
            if let Some(parent) = path.parent() {
                let images_dir = parent.join("evidence");
                let _ = std::fs::create_dir_all(&images_dir);
                images_dir
            } else {
                // Fallback if no parent directory
                let images_dir = std::path::PathBuf::from("./evidence");
                let _ = std::fs::create_dir_all(&images_dir);
                images_dir
            }
        }
        None => {
            // If no session path, use global evidence directory
            let images_dir = std::path::PathBuf::from("./evidence");
            let _ = std::fs::create_dir_all(&images_dir);
            images_dir
        }
    }
}

/// Save a pasted image (texture or pixbuf) to a PNG file and return the relative path
#[allow(dead_code)]
pub fn save_pasted_image(
    texture: Option<&gdk::Texture>,
    pixbuf: Option<&gdk::gdk_pixbuf::Pixbuf>,
    session_path: Option<&Path>,
) -> Option<String> {
    let images_dir = get_session_images_dir(session_path);

    // Generate a unique filename
    let timestamp = chrono::Utc::now().timestamp_millis();
    let filename = format!("evidence_{}.png", timestamp);
    let file_path = images_dir.join(&filename);

    let result = if let Some(tex) = texture {
        save_texture_to_png(tex, &file_path)
    } else if let Some(pb) = pixbuf {
        save_pixbuf_to_png(pb, &file_path)
    } else {
        return None;
    };

    match result {
        Ok(_) => {
            // Return relative path from session directory
            Some(format!("evidence/{}", filename))
        }
        Err(e) => {
            eprintln!("Failed to save pasted image: {}", e);
            None
        }
    }
}