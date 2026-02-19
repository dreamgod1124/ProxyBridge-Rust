fn main() {
    slint_build::compile("ui/appwindow.slint").expect("Slint build failed");

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let icon_path = "icon.ico";
        if std::path::Path::new(icon_path).exists() {
            let mut res = winres::WindowsResource::new();
            res.set_icon(icon_path);
            let _ = res.compile().expect("Failed to compile Windows resource");
        }
    }
}
