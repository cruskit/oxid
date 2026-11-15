use super::*;

fn parse(toml: &str) -> ThemeConfig {
    toml::from_str(toml).unwrap()
}

#[test]
fn colours_are_hexadecimal_only() {
    for good in ["#fff", "#FFFA", "#ff5630", "#ff563080"] {
        assert!(good.parse::<Color>().is_ok(), "{good}");
    }
    assert_eq!("#FF5630".parse::<Color>().unwrap().as_str(), "#ff5630");
    for bad in [
        "",
        "#",
        "ff5630",
        "#ff563",
        "#gggggg",
        "red",
        "rgb(0,0,0)",
        "#fff;}</style><script>",
        "#fff ",
        "var(--x)",
    ] {
        assert!(bad.parse::<Color>().is_err(), "{bad}");
    }
    assert!(toml::from_str::<ThemeConfig>("[light]\naccent = \"red\"").is_err());
    assert!(toml::from_str::<ThemeConfig>("[light]\nacent = \"#fff\"").is_err());
}

#[test]
fn the_default_theme_is_oxid_in_both_modes() {
    let theme = Theme::from_config(&ThemeConfig::default()).unwrap();
    assert_eq!(theme, Theme::default());
    assert_eq!(theme.name, "oxID");
    assert!(theme.is_oxid() && !theme.has_logo() && theme.show_name);
    assert_eq!(theme.light, Palette::light());
    assert_eq!(theme.dark, Palette::dark());
    assert_ne!(theme.light.background, theme.dark.background);
}

/// The `[theme]` section of `oxid.example.toml`, with its settings
/// uncommented.
fn example() -> ThemeConfig {
    #[derive(Deserialize)]
    struct Document {
        theme: ThemeConfig,
    }
    let text = include_str!("../../oxid.example.toml");
    let section = text.split("\n# [theme]\n").nth(1).expect("a theme section");
    let section = section.split("\n[server]").next().unwrap();
    let settings: String = std::iter::once("[theme]")
        .chain(section.lines().filter_map(|line| line.strip_prefix("# ")))
        .filter(|line| line.starts_with('[') || line.contains(" = "))
        .flat_map(|line| [line, "\n"])
        .collect();
    toml::from_str::<Document>(&settings)
        .expect(&settings)
        .theme
}

#[test]
fn the_example_configuration_lists_the_builtin_colours() {
    let example = example();
    example.validate().unwrap();
    assert!(example.name.is_some() && example.logo.is_some() && example.show_name);
    // Every colour is listed, with the value the built-in theme has.
    for (listed, builtin) in [
        (&example.light, Palette::light()),
        (&example.dark, Palette::dark()),
    ] {
        assert_eq!(listed_colours(listed).len(), 12);
        let other = if builtin == Palette::light() {
            Palette::dark()
        } else {
            Palette::light()
        };
        assert_eq!(other.with(listed), builtin);
    }
}

fn listed_colours(palette: &PaletteConfig) -> Vec<&str> {
    [
        &palette.background,
        &palette.surface,
        &palette.surface_muted,
        &palette.border,
        &palette.text,
        &palette.text_muted,
        &palette.primary,
        &palette.primary_text,
        &palette.accent,
        &palette.success,
        &palette.danger,
        &palette.warning,
    ]
    .into_iter()
    .flatten()
    .map(Color::as_str)
    .collect()
}

#[test]
fn a_theme_overrides_only_what_it_sets() {
    let config = parse(
        r##"
            name = " Acme Bank "
            [light]
            accent = "#0055FF"
            [dark]
            accent = "#6699ff"
            background = "#000"
            "##,
    );
    let theme = Theme::from_config(&config).unwrap();
    assert_eq!(theme.name, "Acme Bank");
    assert!(!theme.is_oxid());
    assert_eq!(theme.light.accent.as_str(), "#0055ff");
    assert_eq!(theme.light.text, Palette::light().text);
    assert_eq!(theme.dark.accent.as_str(), "#6699ff");
    assert_eq!(theme.dark.background.as_str(), "#000");
    assert_eq!(theme.dark.surface, Palette::dark().surface);
}

#[test]
fn names_and_logo_settings_are_validated() {
    for bad in [
        "name = \"\"",
        "name = \"  \"",
        "name = \"a\\nb\"",
        "logo_dark = \"dark.png\"",
        "show_name = false",
        "logo = \"logo.gif\"",
        "logo = \"logo\"",
    ] {
        assert!(parse(bad).validate().is_err(), "{bad}");
    }
    let long = format!("name = \"{}\"", "x".repeat(MAX_NAME_LENGTH + 1));
    assert!(parse(&long).validate().is_err());
    for good in [
        "name = \"Acme <Bank> & Co\"",
        "logo = \"logo.SVG\"\nshow_name = false",
        "logo = \"a.png\"\nlogo_dark = \"b.webp\"",
    ] {
        parse(good).validate().unwrap();
    }
}

#[test]
fn logos_are_read_from_their_files() {
    let dir = std::env::temp_dir().join(format!("oxid-theme-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let light = dir.join("logo.svg");
    let dark = dir.join("logo-dark.png");
    std::fs::write(&light, "<svg xmlns=\"http://www.w3.org/2000/svg\"/>").unwrap();
    std::fs::write(&dark, [0x89, b'P', b'N', b'G']).unwrap();

    let mut config = ThemeConfig {
        logo: Some(light.clone()),
        logo_dark: Some(dark),
        ..ThemeConfig::default()
    };
    let theme = Theme::from_config(&config).unwrap();
    assert!(theme.has_logo());
    assert_eq!(theme.logo.as_ref().unwrap().content_type, "image/svg+xml");
    assert_eq!(theme.logo_dark.as_ref().unwrap().content_type, "image/png");
    assert_eq!(theme.logo_dark.unwrap().bytes.len(), 4);

    config.logo_dark = Some(dir.join("missing.png"));
    assert!(Theme::from_config(&config).is_err());
    config.logo_dark = None;
    std::fs::write(&light, "").unwrap();
    assert!(Theme::from_config(&config).is_err(), "an empty logo");

    std::fs::remove_dir_all(&dir).unwrap();
}
