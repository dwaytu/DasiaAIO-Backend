use chrono::{DateTime, NaiveDate};
use serde::Serialize;

const EMPTY_MARKERS: [&str; 5] = ["-", "n/a", "na", "none", "null"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleansingChange {
    pub field: &'static str,
    pub original: String,
    pub cleaned: String,
}

fn is_empty_marker(value: &str) -> bool {
    EMPTY_MARKERS
        .iter()
        .any(|marker| value.eq_ignore_ascii_case(marker))
}

pub fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    let normalized = value
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|text| !text.is_empty())?;

    (!is_empty_marker(&normalized)).then_some(normalized)
}

/// Normalizes spacing around the unambiguous surname/given-name separator without
/// assuming an order for names that have no comma.
pub fn normalize_name(value: Option<&str>) -> Option<String> {
    let normalized = normalize_optional_text(value)?;
    let mut parts = normalized.split(',');
    let first = parts.next()?.trim();
    let second = parts.next();

    if let Some(second) = second {
        if parts.next().is_none() && !first.is_empty() && !second.trim().is_empty() {
            return Some(format!("{}, {}", first, second.trim()));
        }
    }

    Some(normalized)
}

pub fn normalize_identifier(value: Option<&str>) -> Option<String> {
    normalize_optional_text(value).map(|text| {
        text.chars()
            .filter(|character| !character.is_whitespace())
            .flat_map(char::to_uppercase)
            .collect()
    })
}

/// Identifier keys deliberately ignore formatting punctuation. They are used only
/// to find candidates; more than one candidate remains an ambiguous review item.
pub fn canonical_identifier_key(value: Option<&str>) -> Option<String> {
    normalize_identifier(value).map(|text| {
        text.chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .collect()
    })
}

/// Names retain token order. Punctuation and casing differences do not create a
/// false new record, but "FIRST LAST" never matches "LAST FIRST" automatically.
pub fn canonical_name_key(value: Option<&str>) -> Option<String> {
    normalize_name(value).map(|text| {
        text.chars()
            .filter(|character| character.is_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect()
    })
}

pub fn normalize_phone(value: Option<&str>) -> Option<String> {
    let normalized = normalize_optional_text(value)?;
    let digits: String = normalized
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();

    let canonical = if digits.len() == 11 && digits.starts_with('0') {
        format!("+63{}", &digits[1..])
    } else if digits.len() == 12 && digits.starts_with("63") {
        format!("+{}", digits)
    } else if digits.len() == 10 && digits.starts_with('9') {
        format!("+63{}", digits)
    } else {
        normalized
    };

    Some(canonical)
}

pub fn normalize_date(value: Option<&str>) -> Option<String> {
    let normalized = normalize_optional_text(value)?;

    if let Ok(timestamp) = DateTime::parse_from_rfc3339(&normalized) {
        return Some(timestamp.date_naive().format("%Y-%m-%d").to_string());
    }

    for format in ["%Y-%m-%d", "%m/%d/%Y"] {
        if let Ok(date) = NaiveDate::parse_from_str(&normalized, format) {
            return Some(date.format("%Y-%m-%d").to_string());
        }
    }

    Some(normalized)
}

pub fn normalize_firearm_make(value: Option<&str>) -> Option<String> {
    let normalized = normalize_optional_text(value)?;
    let key: String = normalized
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect();

    let canonical = match key.as_str() {
        "ARMSCOR" => "Armscor",
        "ROCKISLAND" => "Rock Island",
        "SMITHWESSON" => "Smith & Wesson",
        _ => normalized.as_str(),
    };

    Some(canonical.to_string())
}

pub fn record_change(
    changes: &mut Vec<CleansingChange>,
    field: &'static str,
    original: Option<&str>,
    cleaned: Option<&str>,
) {
    let original = original.unwrap_or_default();
    let cleaned = cleaned.unwrap_or_default();

    if original != cleaned {
        changes.push(CleansingChange {
            field,
            original: original.to_string(),
            cleaned: cleaned.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_identifier_key, canonical_name_key, normalize_date, normalize_firearm_make,
        normalize_identifier, normalize_name, normalize_optional_text, normalize_phone,
    };

    #[test]
    fn treats_placeholder_values_as_empty() {
        assert_eq!(normalize_optional_text(Some(" N/A ")), None);
        assert_eq!(
            normalize_optional_text(Some("  Guard   Name  ")),
            Some("Guard Name".into())
        );
    }

    #[test]
    fn preserves_name_order_but_repairs_comma_spacing() {
        assert_eq!(
            normalize_name(Some(" AUDITOR,JHON   PAUL ")),
            Some("AUDITOR, JHON PAUL".into())
        );
        assert_eq!(
            normalize_name(Some("JHON PAUL AUDITOR")),
            Some("JHON PAUL AUDITOR".into())
        );
        assert_eq!(
            canonical_name_key(Some("AUDITOR, JHON PAUL")),
            canonical_name_key(Some("auditor jhon paul"))
        );
        assert_ne!(
            canonical_name_key(Some("AUDITOR JHON")),
            canonical_name_key(Some("JHON AUDITOR"))
        );
    }

    #[test]
    fn canonicalizes_phone_and_identifier_variants() {
        assert_eq!(
            normalize_phone(Some("0917 123 4567")),
            Some("+639171234567".into())
        );
        assert_eq!(
            normalize_phone(Some("+63 917-123-4567")),
            Some("+639171234567".into())
        );
        assert_eq!(
            normalize_identifier(Some(" ab c-123 ")),
            Some("ABC-123".into())
        );
        assert_eq!(
            canonical_identifier_key(Some("ABC 123")),
            canonical_identifier_key(Some("abc-123"))
        );
    }

    #[test]
    fn normalizes_known_firearm_brand_variants() {
        assert_eq!(
            normalize_firearm_make(Some(" ARMSCOR ")),
            Some("Armscor".into())
        );
        assert_eq!(
            normalize_firearm_make(Some("rock island")),
            Some("Rock Island".into())
        );
    }

    #[test]
    fn standardizes_supported_date_formats() {
        assert_eq!(
            normalize_date(Some("10/02/2026")),
            Some("2026-10-02".into())
        );
        assert_eq!(
            normalize_date(Some("2026-10-02T12:00:00+08:00")),
            Some("2026-10-02".into())
        );
    }
}
