//! Themes: the name, logo and colours of the pages users see.
//!
//! The pages themselves are the templates in `templates/`. A theme only
//! supplies what differs between one deployment's look and another's: the
//! name the provider goes by, an optional logo, and two palettes of colours,
//! one for light mode and one for dark. The browser picks the palette from
//! the user's system setting (`prefers-color-scheme`); nothing is stored and
//! there is no switch.
//!
//! The built-in theme is oxID's. The `[theme]` section of the configuration
//! overrides any part of it, and whatever it leaves out keeps the oxID value.
//!
//! Colours end up inside a `<style>` element, so only hexadecimal colours
//! are accepted ([`Color`]): nothing a configuration file says can add CSS
//! or markup to a page.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use axum::body::Bytes;
use serde::Deserialize;

/// The name of the built-in theme.
pub(crate) const DEFAULT_NAME: &str = "oxID";

/// Longest theme name accepted. It is shown in headings and the page title.
pub(crate) const MAX_NAME_LENGTH: usize = 60;

/// Largest logo file accepted.
pub(crate) const MAX_LOGO_BYTES: u64 = 512 * 1024;

/// A colour, written in hexadecimal: `#rgb`, `#rgba`, `#rrggbb` or
/// `#rrggbbaa`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Color(String);

impl Color {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A colour known to be valid, for the built-in palettes.
    fn builtin(hex: &'static str) -> Self {
        debug_assert!(hex.parse::<Self>().is_ok(), "{hex}");
        Self(hex.to_owned())
    }
}

/// A theme colour that is not hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not a colour: use hexadecimal, such as #ff5630")]
pub struct NotAColor(String);

impl std::str::FromStr for Color {
    type Err = NotAColor;

    fn from_str(value: &str) -> Result<Self, NotAColor> {
        let digits = value.strip_prefix('#').unwrap_or_default();
        if matches!(digits.len(), 3 | 4 | 6 | 8) && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(NotAColor(value.to_owned()))
        }
    }
}

impl TryFrom<String> for Color {
    type Error = NotAColor;

    fn try_from(value: String) -> Result<Self, NotAColor> {
        value.parse()
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The colours of one mode. Each becomes a CSS custom property in
/// `templates/shell.html`; the softer tints and outlines the pages also use
/// are mixed from these in `templates/shell.css`, so they follow the theme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Palette {
    /// The page, behind everything.
    pub background: Color,
    /// Cards and panels, and the inside of form fields.
    pub surface: Color,
    /// Quieter areas on a surface: boxes, code and hovered buttons.
    pub surface_muted: Color,
    /// Lines between and around things.
    pub border: Color,
    /// Body text.
    pub text: Color,
    /// Secondary text: hints, labels and small print.
    pub text_muted: Color,
    /// The main button.
    pub primary: Color,
    /// Text on the main button.
    pub primary_text: Color,
    /// The brand colour: the logo mark, highlights, links and focus rings.
    pub accent: Color,
    /// Positive states, such as a switch that is on.
    pub success: Color,
    /// Errors.
    pub danger: Color,
    /// Cautions, such as the banner of the technical experience.
    pub warning: Color,
}

impl Palette {
    /// oxID in light mode.
    pub(crate) fn light() -> Self {
        Self {
            background: Color::builtin("#f3f4f8"),
            surface: Color::builtin("#ffffff"),
            surface_muted: Color::builtin("#f5f6f9"),
            border: Color::builtin("#e1e4eb"),
            text: Color::builtin("#0e1320"),
            text_muted: Color::builtin("#5d6577"),
            primary: Color::builtin("#0e1320"),
            primary_text: Color::builtin("#ffffff"),
            accent: Color::builtin("#ff5630"),
            success: Color::builtin("#0a7d55"),
            danger: Color::builtin("#b3261e"),
            warning: Color::builtin("#b7791f"),
        }
    }

    /// oxID in dark mode.
    pub(crate) fn dark() -> Self {
        Self {
            background: Color::builtin("#0b0e16"),
            surface: Color::builtin("#161b27"),
            surface_muted: Color::builtin("#1f2534"),
            border: Color::builtin("#2f3649"),
            text: Color::builtin("#eef0f6"),
            text_muted: Color::builtin("#a3abbd"),
            primary: Color::builtin("#eef0f6"),
            primary_text: Color::builtin("#0e1320"),
            accent: Color::builtin("#ff6b4a"),
            success: Color::builtin("#34c28e"),
            danger: Color::builtin("#ff8f85"),
            warning: Color::builtin("#e9b949"),
        }
    }

    /// This palette with the colours a configuration sets replaced.
    fn with(mut self, overrides: &PaletteConfig) -> Self {
        let apply = |color: &mut Color, value: &Option<Color>| {
            if let Some(value) = value {
                *color = value.clone();
            }
        };
        apply(&mut self.background, &overrides.background);
        apply(&mut self.surface, &overrides.surface);
        apply(&mut self.surface_muted, &overrides.surface_muted);
        apply(&mut self.border, &overrides.border);
        apply(&mut self.text, &overrides.text);
        apply(&mut self.text_muted, &overrides.text_muted);
        apply(&mut self.primary, &overrides.primary);
        apply(&mut self.primary_text, &overrides.primary_text);
        apply(&mut self.accent, &overrides.accent);
        apply(&mut self.success, &overrides.success);
        apply(&mut self.danger, &overrides.danger);
        apply(&mut self.warning, &overrides.warning);
        self
    }
}

/// The colours of one mode, as configured: any subset of a [`Palette`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PaletteConfig {
    pub background: Option<Color>,
    pub surface: Option<Color>,
    pub surface_muted: Option<Color>,
    pub border: Option<Color>,
    pub text: Option<Color>,
    pub text_muted: Option<Color>,
    pub primary: Option<Color>,
    pub primary_text: Option<Color>,
    pub accent: Option<Color>,
    pub success: Option<Color>,
    pub danger: Option<Color>,
    pub warning: Option<Color>,
}

/// The `[theme]` section of the configuration. Everything is optional, and
/// what is left out keeps the value of the built-in oxID theme.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ThemeConfig {
    /// What the provider is called on its pages.
    pub name: Option<String>,
    /// An image shown at the top of every page in place of the oxID mark:
    /// a PNG, SVG, JPEG or WebP file.
    pub logo: Option<PathBuf>,
    /// The logo to use in dark mode. Without one, `logo` is used in both.
    pub logo_dark: Option<PathBuf>,
    /// Show the name beside the logo. Turn it off for a logo that already
    /// spells the name out.
    pub show_name: bool,
    /// Colours in light mode.
    pub light: PaletteConfig,
    /// Colours in dark mode.
    pub dark: PaletteConfig,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            name: None,
            logo: None,
            logo_dark: None,
            show_name: true,
            light: PaletteConfig::default(),
            dark: PaletteConfig::default(),
        }
    }
}

impl ThemeConfig {
    /// Check everything that can be checked without reading the logo files.
    pub fn validate(&self) -> Result<()> {
        if let Some(name) = &self.name {
            ensure!(!name.trim().is_empty(), "name must not be empty");
            ensure!(
                name.chars().count() <= MAX_NAME_LENGTH,
                "name must be at most {MAX_NAME_LENGTH} characters"
            );
            ensure!(
                !name.chars().any(char::is_control),
                "name must not contain control characters"
            );
        }
        ensure!(
            self.logo.is_some() || self.logo_dark.is_none(),
            "logo_dark needs logo to be set as well"
        );
        ensure!(
            self.logo.is_some() || self.show_name,
            "show_name = false needs a logo, or the pages would carry no name"
        );
        for path in self.logo.iter().chain(&self.logo_dark) {
            logo_content_type(path)?;
        }
        Ok(())
    }
}

/// The media type of a logo file, from its extension.
fn logo_content_type(path: &Path) -> Result<&'static str> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    Ok(match extension.as_str() {
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => bail!(
            "logo {} must be a .png, .svg, .jpg or .webp file",
            path.display()
        ),
    })
}

/// A logo image, held in memory and served at a path of its own.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Logo {
    pub content_type: &'static str,
    pub bytes: Bytes,
}

impl fmt::Debug for Logo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logo")
            .field("content_type", &self.content_type)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl Logo {
    fn load(path: &Path) -> Result<Self> {
        let content_type = logo_content_type(path)?;
        let size = std::fs::metadata(path)
            .with_context(|| format!("reading logo {}", path.display()))?
            .len();
        ensure!(
            size <= MAX_LOGO_BYTES,
            "logo {} is larger than {} KiB",
            path.display(),
            MAX_LOGO_BYTES / 1024
        );
        let bytes =
            std::fs::read(path).with_context(|| format!("reading logo {}", path.display()))?;
        ensure!(!bytes.is_empty(), "logo {} is empty", path.display());
        Ok(Self {
            content_type,
            bytes: Bytes::from(bytes),
        })
    }
}

/// The look of the pages: what the templates are rendered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Theme {
    /// What the provider is called.
    pub name: String,
    /// Shown at the top of every page in place of the built-in mark.
    pub logo: Option<Logo>,
    /// The logo in dark mode, when it differs.
    pub logo_dark: Option<Logo>,
    /// Whether the name is shown at the top of the page as well.
    pub show_name: bool,
    pub light: Palette,
    pub dark: Palette,
}

impl Default for Theme {
    /// The built-in oxID theme.
    fn default() -> Self {
        Self {
            name: DEFAULT_NAME.to_owned(),
            logo: None,
            logo_dark: None,
            show_name: true,
            light: Palette::light(),
            dark: Palette::dark(),
        }
    }
}

impl Theme {
    /// The theme a configuration describes: the oxID theme, with whatever
    /// the configuration sets replaced. Reads the logo files.
    pub(crate) fn from_config(config: &ThemeConfig) -> Result<Self> {
        config.validate()?;
        let logo = |path: &Option<PathBuf>| path.as_deref().map(Logo::load).transpose();
        Ok(Self {
            name: config
                .name
                .as_deref()
                .map_or(DEFAULT_NAME, str::trim)
                .to_owned(),
            logo: logo(&config.logo)?,
            logo_dark: logo(&config.logo_dark)?,
            show_name: config.show_name,
            light: Palette::light().with(&config.light),
            dark: Palette::dark().with(&config.dark),
        })
    }

    /// Whether this is oxID by name, which gets its two-tone wordmark.
    pub(crate) fn is_oxid(&self) -> bool {
        self.name == DEFAULT_NAME
    }

    /// Whether the pages load an image, which their content security policy
    /// must then allow.
    pub(crate) fn has_logo(&self) -> bool {
        self.logo.is_some()
    }
}

#[cfg(test)]
mod tests;
