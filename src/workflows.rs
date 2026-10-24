//! Bounded declarative automation. File paths and passwords are never presets.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(untagged)]
pub enum Step {
    Legacy(String),
    Configured(KeyStep),
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct KeyStep {
    pub operation: String,
    #[serde(default = "default_selection")]
    pub selection: String,
    #[serde(default)]
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub require_all_signers: bool,
}
fn default_selection() -> String {
    "notepad".into()
}
fn is_default_pattern(value: &str) -> bool {
    value == default_pattern()
}
fn default_pattern() -> String {
    "{stem}-{index}.processed".into()
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub name: String,
    pub steps: Vec<Step>,
    #[serde(
        default = "default_pattern",
        skip_serializing_if = "is_default_pattern"
    )]
    pub output_pattern: String,
}

pub fn fingerprint(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
}
pub fn validate_keys(keys: &[String]) -> Result<()> {
    ensure!(keys.len() <= 16, "Choose at most 16 keys per step");
    let mut unique = HashSet::new();
    ensure!(
        keys.iter()
            .all(|key| fingerprint(key) && unique.insert(key)),
        "Key fingerprints must be unique full uppercase fingerprints"
    );
    Ok(())
}

pub fn validate(presets: &[Preset]) -> Result<()> {
    ensure!(presets.len() <= 32, "At most 32 workflows are supported");
    let mut names = HashSet::new();
    for preset in presets {
        ensure!(
            !preset.name.trim().is_empty()
                && preset.name.chars().count() <= 80
                && !preset
                    .name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '\u{fffe}' | '\u{ffff}')),
            "Workflow names must have 1–80 characters without controls"
        );
        ensure!(
            names.insert(preset.name.trim().to_lowercase()),
            "Workflow names must be unique"
        );
        ensure!(
            (1..=32).contains(&preset.steps.len()),
            "A workflow needs 1–32 steps"
        );
        ensure!(
            !preset.output_pattern.trim().is_empty()
                && preset.output_pattern.chars().count() <= 120
                && !preset
                    .output_pattern
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\' | '\u{fffe}' | '\u{ffff}')),
            "Output pattern must be a filename without folders or controls (1–120 characters)"
        );
        let mut pattern = preset.output_pattern.clone();
        for token in ["{stem}", "{name}", "{ext}", "{index}", "{workflow}"] {
            pattern = pattern.replace(token, "");
        }
        ensure!(
            !pattern.contains(['{', '}']),
            "Unknown filename pattern token"
        );
        for step in &preset.steps {
            let operation = match step {
                Step::Legacy(op) => op,
                Step::Configured(config) => &config.operation,
            };
            ensure!(
                matches!(
                    operation.as_str(),
                    "encrypt" | "decrypt" | "sign" | "verify"
                ),
                "Workflows support only encrypt, decrypt, sign and verify"
            );
            if let Step::Configured(config) = step {
                ensure!(
                    matches!(config.selection.as_str(), "notepad" | "keys"),
                    "Unsupported workflow key selection"
                );
                validate_keys(&config.fingerprints)?;
                ensure!(
                    (config.selection == "keys" && !config.fingerprints.is_empty())
                        || (config.selection == "notepad" && config.fingerprints.is_empty()),
                    "Explicit steps need keys; Notepad steps inherit the current selection"
                );
                ensure!(
                    !config.require_all_signers
                        || (operation == "verify" && config.selection == "keys"),
                    "Required signers apply only to verification with explicit keys"
                );
            }
        }
    }
    Ok(())
}

pub fn defaults() -> Vec<Preset> {
    vec![
        Preset {
            name: "Sign then encrypt".into(),
            steps: vec![Step::Legacy("sign".into()), Step::Legacy("encrypt".into())],
            output_pattern: "{stem}-{index}.asc".into(),
        },
        Preset {
            name: "Decrypt and verify".into(),
            steps: vec![
                Step::Legacy("decrypt".into()),
                Step::Legacy("verify".into()),
            ],
            output_pattern: "{stem}-{index}.txt".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn legacy_and_explicit_steps_are_portable_and_bounded() -> Result<()> {
        let fp = "A".repeat(40);
        let preset: Preset = serde_json::from_value(
            json!({"name":"Rotate keys","steps":["decrypt",{"operation":"sign","selection":"keys","fingerprints":[fp]},"encrypt"],"output_pattern":"{stem}-{workflow}-{index}.asc"}),
        )?;
        validate(std::slice::from_ref(&preset))?;
        let roundtrip: Preset = serde_json::from_value(serde_json::to_value(&preset)?)?;
        validate(&[roundtrip])?;
        for value in [
            json!({"name":"bad","steps":[{"operation":"sign","selection":"keys","fingerprints":[]}]}),
            json!({"name":"bad","steps":[{"operation":"sign","selection":"keys","fingerprints":["A".repeat(40),"A".repeat(40)]}]}),
            json!({"name":"bad","steps":[{"operation":"sign","selection":"notepad","fingerprints":["A".repeat(40)]}]}),
            json!({"name":"bad","steps":[{"operation":"decrypt","selection":"keys","fingerprints":["A".repeat(40)],"require_all_signers":true}]}),
            json!({"name":"bad","steps":["shell"]}),
            json!({"name":"bad","steps":["encrypt"],"output_pattern":"../{name}"}),
            json!({"name":"bad","steps":["encrypt"],"output_pattern":"{unknown}.asc"}),
            json!({"name":"bad","steps":vec!["encrypt";33]}),
        ] {
            let preset: Preset = serde_json::from_value(value)?;
            assert!(validate(&[preset]).is_err());
        }
        assert!(
            serde_json::from_value::<Preset>(
                json!({"name":"secret","steps":[{"operation":"sign","password":"never stored"}]})
            )
            .is_err()
        );
        let legacy: Preset =
            serde_json::from_value(json!({"name":"legacy","steps":["sign","encrypt"]}))?;
        assert_eq!(legacy.output_pattern, "{stem}-{index}.processed");
        Ok(())
    }
}
