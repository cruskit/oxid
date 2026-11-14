use serde_json::json;

use super::*;
use crate::testing::html::{Page, has_id, text_of};

fn text(value: &str) -> ClaimValue {
    ClaimValue::Text(value.to_owned())
}

#[test]
fn values_are_shown_as_text() {
    assert_eq!(ClaimValue::of("given_name", &json!("A<b>")), text("A<b>"));
    assert_eq!(ClaimValue::of("over18", &json!(true)), text("Yes"));
    assert_eq!(ClaimValue::of("over65", &json!(false)), text("No"));
    assert_eq!(
        ClaimValue::of(
            "address",
            &json!({"street_address": "1 Main St", "locality": "Sydney",
                        "region": "NSW", "postal_code": "2000"})
        ),
        text("1 Main St, Sydney, NSW 2000")
    );
    assert_eq!(
        ClaimValue::of(
            "beneficiary_account_au",
            &json!({"account_bsb": "123-456", "some_thing": "<x>"})
        ),
        ClaimValue::Members(vec![
            Member {
                label: "BSB".to_owned(),
                text: "123-456".to_owned()
            },
            Member {
                label: "Some thing".to_owned(),
                text: "<x>".to_owned()
            },
        ])
    );
}

#[test]
fn the_consent_template_escapes_what_it_shows() {
    let item = |name: &str, essential: bool| ConsentItem {
        name: name.to_owned(),
        label: format!("Label of {name}"),
        essential,
    };
    let theme = Theme::default();
    let template = ConsentTemplate {
        theme: &theme,
        form: FormTarget::new("c\"srf", "rp", "urn:x"),
        client_name: "R&P <b>",
        user_name: "Al <i>".to_owned(),
        purpose: Some("see <this>"),
        required: vec![ClaimRow::new(
            &item("beneficiary_account_au", true),
            Some(&json!({"account_bsb": "<1>"})),
            false,
        )],
        optional: vec![
            ClaimRow::new(&item("given_name", false), Some(&json!("A<b>")), true),
            ClaimRow::new(&item("email", false), None, true),
        ],
        limit: "5 minutes".to_owned(),
    };
    let html = render(&template);
    for raw in ["<b>", "<i>", "<this>", "<1>", "c\"srf"] {
        assert!(!html.contains(raw), "{raw} in {html}");
    }
    assert!(html.contains("<em>BSB:</em> &#60;1&#62;"), "{html}");
    assert!(
        Page::parse(&html)
            .checkboxes(true)
            .contains(&"share_given_name".to_owned())
    );
    // A claim the user has no value for is listed, without a switch.
    assert!(text_of(&html, "value-email").starts_with("Not on file"));
    assert!(!html.contains("share_email"));
    assert!(has_id(&html, "share-all"));
}
