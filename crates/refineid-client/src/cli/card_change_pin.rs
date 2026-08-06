// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! `card change-pin1` / `card change-pin2` typed arguments.

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use refineid_lib_core::apdu::status_word::PinRetries;
use refineid_lib_core::auth::PinStatus;
use refineid_lib_core::identity::TokenSerial;
use refineid_lib_core::pin_retry_risk::PinRetryRisk;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_pin::PinManageSlot;

const LOW_RETRY_CONFIRMATION: &str = "I AM REALLY REALLY SURE";

/// CLI-only, card/slot/counter-bound permission for one low-retry operation.
/// Private fields prevent interfacing libraries from constructing it.
pub(crate) struct LowRetryAuthorization {
    serial: TokenSerial,
    slot: PinManageSlot,
    retries: PinRetries,
}

impl LowRetryAuthorization {
    pub(crate) fn permits(
        &self,
        serial: &TokenSerial,
        slot: PinManageSlot,
        status: PinStatus,
    ) -> bool {
        self.serial == *serial
            && self.slot == slot
            && matches!(status, PinStatus::Remaining(retries) if retries == self.retries)
    }
}

fn authorize_low_retry(
    cmd: &str,
    serial: &TokenSerial,
    slot: PinManageSlot,
    status: PinStatus,
) -> Result<Option<LowRetryAuthorization>, std::process::ExitCode> {
    use crate::exit_status::ExitStatus;

    let retries = match status {
        PinStatus::Remaining(retries) => retries,
        PinStatus::Verified => return Ok(None),
        PinStatus::Locked => {
            eprintln!("{cmd}: {} is locked; refusing", slot.label());
            return Err(ExitStatus::CardCredentialRejected.into());
        }
        PinStatus::NoInfo | PinStatus::Other(_) => {
            eprintln!("{cmd}: retry status is uncertain; refusing");
            return Err(ExitStatus::RuntimeFailure.into());
        }
    };
    match PinRetryRisk::from_retries(retries) {
        Some(risk) if risk.permits_consumer() => return Ok(None),
        Some(risk) if risk.requires_expert_confirmation() => {}
        Some(PinRetryRisk::DefencesFallen) => {
            eprintln!(
                "{cmd}: {} has no attempts remaining; refusing",
                slot.label()
            );
            return Err(ExitStatus::CardCredentialRejected.into());
        }
        Some(_) | None => {
            eprintln!("{cmd}: retry status is invalid; refusing");
            return Err(ExitStatus::RuntimeFailure.into());
        }
    }
    if !std::io::stdin().is_terminal() {
        eprintln!("{cmd}: low-retry authorization requires an interactive terminal");
        return Err(ExitStatus::BadInvocation.into());
    }

    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "{cmd}: WARNING: {} has only {retries} attempt(s) remaining.",
        slot.label()
    );
    let _ = writeln!(
        stderr,
        "A wrong value will reduce the expert recovery margin. Are you really really sure?"
    );
    let _ = write!(stderr, "Type {LOW_RETRY_CONFIRMATION} to continue: ");
    let _ = stderr.flush();

    let mut confirmation = String::new();
    if std::io::stdin()
        .lock()
        .read_line(&mut confirmation)
        .is_err()
        || confirmation.trim_end_matches(['\r', '\n']) != LOW_RETRY_CONFIRMATION
    {
        eprintln!("{cmd}: low-retry operation cancelled");
        return Err(ExitStatus::BadInvocation.into());
    }
    Ok(Some(LowRetryAuthorization {
        serial: serial.clone(),
        slot,
        retries,
    }))
}

/// Parsed `card change-pin{1,2} [--reader SUBSTR]` arguments.
///
/// `slot` is set by the dispatcher at parse time -- which
/// subcommand fired (`change-pin1` vs `change-pin2`) is the
/// only signal for PIN1-vs-PIN2 identity, and we capture it
/// into the typed struct so [`Self::run`] takes no extra
/// argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePinArgs {
    /// Which PIN slot to rotate; set by the dispatcher at parse
    /// time.
    pub slot: PinManageSlot,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
}

impl ChangePinArgs {
    /// Execute the `card change-pin{1,2}` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        use crate::exit_status::ExitStatus;
        let Self {
            slot,
            reader_filter,
        } = self;
        let cmd = match slot {
            PinManageSlot::Pin1 => "card change-pin1",
            PinManageSlot::Pin2 => "card change-pin2",
        };
        let label = slot.label();
        let backend = refineid_lib_pcsc::PcscBackend;
        let typed_reader_filter = reader_filter
            .as_deref()
            .map(refineid_lib_core::backend::ReaderFilter::new);
        let session =
            match crate::card_pin::establish_trusted_session(backend, typed_reader_filter.as_ref())
            {
                Ok(s) => s,
                Err(crate::card_pin::CardPinError::ReaderPick(pe)) => {
                    return super::util::reader_pick_exit(cmd, &pe);
                }
                Err(e) => {
                    eprintln!("{cmd}: {e}");
                    return ExitStatus::RuntimeFailure.into();
                }
            };
        let ctx = session.into_pin_management_context();
        let retry_status = match crate::card_pin::probe_pin_status_for_cli(backend, &ctx, slot) {
            Ok(status) => status,
            Err(error) => {
                eprintln!("{cmd}: {error}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        let authorization = match authorize_low_retry(cmd, ctx.bound_serial(), slot, retry_status) {
            Ok(authorization) => authorization,
            Err(exit) => return exit,
        };
        let (current_env, new_env) = match slot {
            PinManageSlot::Pin1 => ("REFINEID_CURRENT_PIN1", "REFINEID_NEW_PIN1"),
            PinManageSlot::Pin2 => ("REFINEID_CURRENT_PIN2", "REFINEID_NEW_PIN2"),
        };
        let current =
            match super::util::pin_env_or_prompt(cmd, current_env, &format!("current {label}: ")) {
                Ok(p) => p,
                Err(exit) => return exit,
            };
        let new1 = match super::util::new_pin_env_or_prompt(cmd, new_env, label, None) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let options = crate::card_pin::ChangePinOptions {
            slot,
            current,
            new: new1,
            reader_filter,
        };
        match crate::card_pin::change_pin_first_for_cli(backend, ctx, options, authorization) {
            Ok(report) => {
                print!("{report}");
                match report.outcome {
                    refineid_lib_core::auth::ChangePinOutcome::Ok => ExitStatus::Ok.into(),
                    refineid_lib_core::auth::ChangePinOutcome::WrongCurrentPin { .. }
                    | refineid_lib_core::auth::ChangePinOutcome::Locked => {
                        ExitStatus::CardCredentialRejected.into()
                    }
                    refineid_lib_core::auth::ChangePinOutcome::LengthError
                    | refineid_lib_core::auth::ChangePinOutcome::Other(_) => {
                        ExitStatus::RuntimeFailure.into()
                    }
                }
            }
            Err(crate::card_pin::CardPinError::ReaderPick(pe)) => {
                super::util::reader_pick_exit(cmd, &pe)
            }
            Err(e @ crate::card_pin::CardPinError::PinPolicy(_)) => {
                eprintln!("{cmd}: {e}");
                ExitStatus::CardCredentialRejected.into()
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice for the given
    /// `slot`. The caller (the verb dispatcher) selects the
    /// slot from which subcommand fired and we carry it into
    /// the typed [`ChangePinArgs`] so [`Self::run`] needs no
    /// extra argument.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(slot: PinManageSlot, argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let cmd = match slot {
            PinManageSlot::Pin1 => VerbTag::CardChangePin1,
            PinManageSlot::Pin2 => VerbTag::CardChangePin2,
        };
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd,
                        got: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            slot,
            reader_filter,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_empty_argv_with_no_reader_filter() -> TestResult {
        let a = ChangePinArgs::parse(PinManageSlot::Pin1, argv(&[]))?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")?;
        check(&a.slot, &PinManageSlot::Pin1, "slot")
    }

    #[test]
    fn parses_reader_filter() -> TestResult {
        let a = ChangePinArgs::parse(PinManageSlot::Pin2, argv(&["--reader", "ACS"]))?;
        check(&a.reader_filter.as_deref(), &Some("ACS"), "reader_filter")?;
        check(&a.slot, &PinManageSlot::Pin2, "slot")
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = ChangePinArgs::parse(PinManageSlot::Pin1, argv(&["--enforce-strong"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }

    #[test]
    fn reader_without_value_rejected() -> TestResult {
        let r = ChangePinArgs::parse(PinManageSlot::Pin1, argv(&["--reader"]));
        check_true(
            matches!(r, Err(ArgParseError::MissingValue { .. })),
            "MissingValue",
        )
    }

    #[test]
    fn low_retry_authorization_is_card_slot_and_counter_bound() -> TestResult {
        let serial = TokenSerial::new("CARD-A-FULL-SERIAL".to_owned());
        let other_serial = TokenSerial::new("CARD-B-FULL-SERIAL".to_owned());
        let two = PinRetries::from_nibble(2).ok_or("two retries")?;
        let one = PinRetries::from_nibble(1).ok_or("one retry")?;
        let authorization = LowRetryAuthorization {
            serial: serial.clone(),
            slot: PinManageSlot::Pin1,
            retries: two,
        };

        check_true(
            authorization.permits(&serial, PinManageSlot::Pin1, PinStatus::Remaining(two)),
            "matching authorization",
        )?;
        check_true(
            !authorization.permits(
                &other_serial,
                PinManageSlot::Pin1,
                PinStatus::Remaining(two),
            ),
            "different card refused",
        )?;
        check_true(
            !authorization.permits(&serial, PinManageSlot::Pin2, PinStatus::Remaining(two)),
            "different slot refused",
        )?;
        check_true(
            !authorization.permits(&serial, PinManageSlot::Pin1, PinStatus::Remaining(one)),
            "changed counter refused",
        )
    }
}
