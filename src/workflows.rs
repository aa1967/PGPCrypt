//! Bounded, declarative Notepad presets. No scripts, file actions or credentials.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub name: String,
    pub steps: Vec<String>,
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
            (1..=8).contains(&preset.steps.len()),
            "A workflow needs 1–8 steps"
        );
        ensure!(
            preset
                .steps
                .iter()
                .all(|step| matches!(step.as_str(), "encrypt" | "decrypt" | "sign" | "verify")),
            "Workflows support only encrypt, decrypt, sign and verify"
        );
    }
    Ok(())
}

pub fn defaults() -> Vec<Preset> {
    vec![
        Preset {
            name: "Sign then encrypt".into(),
            steps: vec!["sign".into(), "encrypt".into()],
        },
        Preset {
            name: "Decrypt and verify".into(),
            steps: vec!["decrypt".into(), "verify".into()],
        },
    ]
}
