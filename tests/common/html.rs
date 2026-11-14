//! Reading pages in tests. The HTML is parsed and elements are found by
//! `id` or `name`, so tests do not depend on how a template formats a tag
//! or orders its attributes, and text comes back with entities decoded.
//!
//! Shared by the integration tests and, through `#[path]`, the unit tests.

use scraper::{ElementRef, Html, Selector};

/// A parsed page.
#[derive(Debug)]
pub struct Page(Html);

fn selector(css: &str) -> Selector {
    Selector::parse(css).unwrap_or_else(|e| panic!("bad selector {css}: {e}"))
}

impl Page {
    pub fn parse(html: &str) -> Self {
        Self(Html::parse_document(html))
    }

    /// Every element matching a CSS selector.
    pub fn select(&self, css: &str) -> Vec<ElementRef<'_>> {
        self.0.select(&selector(css)).collect()
    }

    /// The element with `id`, if there is one.
    pub fn by_id(&self, id: &str) -> Option<ElementRef<'_>> {
        self.select(&format!("[id=\"{id}\"]")).into_iter().next()
    }

    pub fn has_id(&self, id: &str) -> bool {
        self.by_id(id).is_some()
    }

    /// The text of the element with `id`, nested elements included.
    pub fn text_of(&self, id: &str) -> String {
        self.by_id(id)
            .unwrap_or_else(|| panic!("no element {id}"))
            .text()
            .collect()
    }

    /// An attribute of the element with `id`.
    pub fn attr_of(&self, id: &str, attr: &str) -> Option<String> {
        self.by_id(id)?.value().attr(attr).map(str::to_owned)
    }

    /// Whether the element with `id` has the boolean attribute `attr`
    /// (`checked`, `hidden`, `selected`).
    pub fn flag(&self, id: &str, attr: &str) -> bool {
        self.attr_of(id, attr).is_some()
    }

    /// The `value` of the first form field named `name`.
    pub fn field(&self, name: &str) -> String {
        self.select(&format!("[name=\"{name}\"]"))
            .first()
            .and_then(|field| field.value().attr("value"))
            .unwrap_or_else(|| panic!("no field {name}"))
            .to_owned()
    }

    /// Names of the checkboxes, or of those ticked when the page loads.
    pub fn checkboxes(&self, only_ticked: bool) -> Vec<String> {
        self.select("input[type=\"checkbox\"][name]")
            .into_iter()
            .filter(|input| !only_ticked || input.value().attr("checked").is_some())
            .filter_map(|input| input.value().attr("name").map(str::to_owned))
            .collect()
    }

    /// The values of the options of the `<select>` with `id`.
    pub fn options(&self, id: &str) -> Vec<String> {
        self.select(&format!("select[id=\"{id}\"] option"))
            .into_iter()
            .filter_map(|option| option.value().attr("value").map(str::to_owned))
            .collect()
    }

    /// The value of the selected option of the `<select>` with `id`.
    pub fn selected(&self, id: &str) -> Option<String> {
        self.select(&format!("select[id=\"{id}\"] option[selected]"))
            .first()
            .and_then(|option| option.value().attr("value").map(str::to_owned))
    }
}

/// Whether `html` has an element with `id`.
pub fn has_id(html: &str, id: &str) -> bool {
    Page::parse(html).has_id(id)
}

/// The text of the element with `id` on `html`.
pub fn text_of(html: &str, id: &str) -> String {
    Page::parse(html).text_of(id)
}
