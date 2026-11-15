//! Enums with names on the wire: in configuration, form fields, stored
//! records and protocol messages.
//!
//! [`wire_enum!`] declares the enum and its names in one table, and derives
//! everything that converts between the two (`as_str`, `ALL`, `FromStr`,
//! `Display`, and serde), so a name cannot be spelt one way in one place
//! and another way elsewhere.

/// A name that is not one of an enum's wire names.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {what} '{value}' (expected one of: {})", expected.join(", "))]
pub struct UnknownName {
    what: &'static str,
    value: String,
    expected: Vec<&'static str>,
}

impl UnknownName {
    pub(crate) fn new(what: &'static str, value: &str, expected: Vec<&'static str>) -> Self {
        Self {
            what,
            value: value.to_owned(),
            expected,
        }
    }
}

/// Declare an enum whose variants have wire names:
///
/// ```ignore
/// wire_enum! {
///     /// What a form asks for.
///     pub(crate) enum Action ("action") {
///         SignIn = "sign-in",
///         Deny = "deny",
///     }
/// }
/// ```
///
/// The string in parentheses names the enum in error messages.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident ($what:literal) {
            $( $(#[$vmeta:meta])* $variant:ident = $wire:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every variant, in declaration order.
            #[allow(dead_code, reason = "generated for every wire enum; not all list theirs")]
            $vis const ALL: &[Self] = &[$(Self::$variant),+];

            /// The name on the wire.
            $vis const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::wire::UnknownName;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($wire => Ok(Self::$variant),)+
                    _ => Err($crate::wire::UnknownName::new(
                        $what,
                        value,
                        vec![$($wire),+],
                    )),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use wire_enum;

#[cfg(test)]
mod tests {
    wire_enum! {
        enum Colour ("colour") {
            Red = "red",
            DarkBlue = "dark-blue",
        }
    }

    #[test]
    fn names_round_trip_through_every_conversion() {
        for colour in Colour::ALL {
            assert_eq!(colour.as_str().parse::<Colour>().unwrap(), *colour);
            assert_eq!(colour.to_string(), colour.as_str());
            let json = serde_json::to_string(colour).unwrap();
            assert_eq!(json, format!("\"{}\"", colour.as_str()));
            assert_eq!(serde_json::from_str::<Colour>(&json).unwrap(), *colour);
        }
        assert_eq!(Colour::ALL, [Colour::Red, Colour::DarkBlue]);
    }

    #[test]
    fn unknown_names_say_what_was_expected() {
        let error = "green".parse::<Colour>().unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown colour 'green' (expected one of: red, dark-blue)"
        );
        let error = serde_json::from_str::<Colour>("\"green\"").unwrap_err();
        assert!(error.to_string().contains("expected one of"), "{error}");
    }
}
