//! The one admission guard that needs no history: a deadline after which
//! the trigger admits nothing.

use anyhow::{Context, Result};
use chrono::{DateTime, FixedOffset, Utc};

use super::Trigger;

fn timestamp(value: &str) -> Result<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).context("expected an RFC 3339 timestamp")
}

pub(super) fn validate(trigger: &Trigger) -> Result<()> {
    if let Some(deadline) = &trigger.stop_after {
        timestamp(deadline).context("[trigger] stop-after")?;
    }
    Ok(())
}

pub(super) fn check(trigger: &Trigger) -> Result<Option<String>> {
    let now = Utc::now().fixed_offset();
    if trigger
        .stop_after
        .as_deref()
        .map(timestamp)
        .transpose()?
        .is_some_and(|deadline| now >= deadline)
    {
        return Ok(Some("the trigger's stop-after deadline has passed".into()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines_and_invalid_settings() {
        for (settings, valid, refused) in [
            ("stop-after = '2000-01-01T00:00:00Z'", true, true),
            ("stop-after = '2999-01-01T00:00:00+01:00'", true, false),
            ("stop-after = 'tomorrow'", false, false),
        ] {
            let trigger: Trigger =
                toml::from_str(&format!("events = ['schedule']\n{settings}")).unwrap();
            assert_eq!(validate(&trigger).is_ok(), valid, "{settings}");
            if valid {
                assert_eq!(check(&trigger).unwrap().is_some(), refused, "{settings}");
            }
        }
    }

    #[test]
    fn history_guards_are_not_settings() {
        // An unknown key fails closed rather than being a guard that does
        // nothing.
        for settings in ["cooldown = 60", "max-runs-per-user = 1"] {
            assert!(
                toml::from_str::<Trigger>(&format!("events = ['schedule']\n{settings}")).is_err(),
                "{settings}"
            );
        }
    }
}
