//! Port of relay.go modelNameMap + normalizeBody's model normalization.
//!
//! Upstream model names are case-sensitive; clients send lowercase aliases.
//! Casing aligned to zai-org/ZCode official-glm-selection migration SQL.

/// Client alias (lowercase) -> official upstream name. Mirrors Go modelNameMap.
pub static MODEL_NAME_MAP: &[(&str, &str)] = &[
    ("glm-5.3", "GLM-5.3"),
    ("glm-5.3-flash", "GLM-5.3-Flash"),
    ("glm-5v-turbo", "GLM-5V-Turbo"),
    ("glm-5.2", "GLM-5.2"),
    ("glm-5.1", "GLM-5.1"),
    ("glm-5", "GLM-5"),
    ("glm-5-turbo", "GLM-5-Turbo"),
    ("glm-turbo", "GLM-5-Turbo"),
    ("glm-4.7", "GLM-4.7"),
    ("glm-4.6", "GLM-4.6"),
    ("glm-4.5", "GLM-4.5"),
    ("glm-4.5-air", "GLM-4.5-Air"),
    ("glm-4.5v", "GLM-4.5V"),
    ("glm-4.5-flash", "GLM-4.5-Flash"),
    ("glm-5.1-highspeed", "GLM-5.1-Highspeed"),
    ("glm-4.7-flash", "GLM-4.7-Flash"),
    ("glm-4.7-flashx", "GLM-4.7-FlashX"),
    ("glm-4.6v", "GLM-4.6V"),
    ("glm-4.6v-flash", "GLM-4.6V-Flash"),
    ("glm-4.6v-flashx", "GLM-4.6V-FlashX"),
    ("glm-4.1v-thinking-flash", "GLM-4.1V-Thinking-Flash"),
    ("glm-4.1v-thinking-flashx", "GLM-4.1V-Thinking-FlashX"),
    ("glm-4-flash-250414", "GLM-4-Flash-250414"),
    ("glm-4-flashx-250414", "GLM-4-FlashX-250414"),
    ("glm-4v-flash", "GLM-4V-Flash"),
];

/// Strip everything after the first `/` (Go SplitN: parts[1] of 2), trim,
/// lowercase-alias lookup, else case-insensitive match against the configured
/// catalog, else the trimmed input unchanged.
pub fn normalize_model_name(model: &str, config_models: &[&str]) -> String {
    let mut m = model.to_string();
    if let Some(idx) = m.find('/') {
        m = m[idx + 1..].to_string();
    }
    let m = m.trim();
    if let Some((_, official)) = MODEL_NAME_MAP.iter().find(|(a, _)| *a == m.to_lowercase()) {
        return official.to_string();
    }
    for c in config_models {
        if c.eq_ignore_ascii_case(m) {
            return (*c).to_string();
        }
    }
    m.to_string()
}

/// Gateway-key whitelist lookup: alias table on the trimmed lowercase input,
/// else the input unchanged.
pub fn canonical_model_name(model: &str) -> String {
    let trimmed = model.trim();
    if let Some((_, official)) = MODEL_NAME_MAP
        .iter()
        .find(|(a, _)| *a == trimmed.to_lowercase())
    {
        return official.to_string();
    }
    model.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_lookup_and_casing() {
        assert_eq!(normalize_model_name("glm-5.3", &[]), "GLM-5.3");
        assert_eq!(normalize_model_name("GLM-5.3", &[]), "GLM-5.3");
        assert_eq!(
            normalize_model_name("builtin:zai/glm-5.3-flash", &[]),
            "GLM-5.3-Flash"
        );
    }

    #[test]
    fn config_catalog_case_insensitive() {
        assert_eq!(
            normalize_model_name("some-new-model", &["GLM-5.3", "Some-New-Model"]),
            "Some-New-Model"
        );
    }

    #[test]
    fn unknown_passthrough() {
        assert_eq!(
            normalize_model_name("  mystery-model  ", &[]),
            "mystery-model"
        );
    }

    #[test]
    fn canonical_whitelist_shape() {
        assert_eq!(canonical_model_name("glm-5.3-flash"), "GLM-5.3-Flash");
        assert_eq!(canonical_model_name("other"), "other");
    }
}
