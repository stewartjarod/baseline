use crate::rules::ast;
use crate::config::RuleConfig;
use crate::rules::banned_dependency::BannedDependencyRule;
use crate::rules::banned_import::BannedImportRule;
use crate::rules::banned_pattern::BannedPatternRule;
use crate::rules::file_presence::FilePresenceRule;
use crate::rules::ratchet::RatchetRule;
use crate::rules::required_pattern::RequiredPatternRule;
use crate::rules::tailwind_dark_mode::TailwindDarkModeRule;
use crate::rules::tailwind_theme_tokens::TailwindThemeTokensRule;
use crate::rules::window_pattern::WindowPatternRule;
use crate::rules::{Rule, RuleBuildError};
use std::fmt;

#[derive(Debug)]
pub enum FactoryError {
    UnknownRuleType(String),
    BuildError(RuleBuildError),
}

impl fmt::Display for FactoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FactoryError::UnknownRuleType(t) => write!(f, "unknown rule type: '{}'", t),
            FactoryError::BuildError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for FactoryError {}

impl From<RuleBuildError> for FactoryError {
    fn from(e: RuleBuildError) -> Self {
        FactoryError::BuildError(e)
    }
}

/// Build a rule instance from a type string and config.
pub fn build_rule(rule_type: &str, config: &RuleConfig) -> Result<Box<dyn Rule>, FactoryError> {
    match rule_type {
        "tailwind-dark-mode" => Ok(Box::new(TailwindDarkModeRule::new(config)?)),
        "tailwind-theme-tokens" => Ok(Box::new(TailwindThemeTokensRule::new(config)?)),
        "ratchet" => Ok(Box::new(RatchetRule::new(config)?)),
        "banned-pattern" => Ok(Box::new(BannedPatternRule::new(config)?)),
        "banned-import" => Ok(Box::new(BannedImportRule::new(config)?)),
        "banned-dependency" => Ok(Box::new(BannedDependencyRule::new(config)?)),
        "required-pattern" => Ok(Box::new(RequiredPatternRule::new(config)?)),
        "file-presence" => Ok(Box::new(FilePresenceRule::new(config)?)),
        "window-pattern" => Ok(Box::new(WindowPatternRule::new(config)?)),
"max-component-size" => Ok(Box::new(ast::MaxComponentSizeRule::new(config)?)),
"no-nested-components" => Ok(Box::new(ast::NoNestedComponentsRule::new(config)?)),
"prefer-use-reducer" => Ok(Box::new(ast::PreferUseReducerRule::new(config)?)),
"no-cascading-set-state" => Ok(Box::new(ast::NoCascadingSetStateRule::new(config)?)),
"require-img-alt" => Ok(Box::new(ast::RequireImgAltRule::new(config)?)),
        _ => Err(FactoryError::UnknownRuleType(rule_type.to_string())),
    }
}
