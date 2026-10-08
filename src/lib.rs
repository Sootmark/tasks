//! Windows scheduled tasks, for forensics: the task XML files of
//! `Windows\System32\Tasks` (Vista and later) and the `.job` files of
//! `Windows\Tasks` (XP and 2003, and what `at` and older installers still
//! write), read into what runs, as whom, when, and whether it is enabled
//! or hidden.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let task = tasks::task::read(&std::fs::read(r"C:\Windows\System32\Tasks\Updater")?);
//! for action in &task.actions {
//!     println!("{:?} runs {} (hidden: {})", task.uri, action.summary(), task.hidden());
//! }
//! let job = tasks::job::read(&std::fs::read(r"C:\Windows\Tasks\At1.job")?)?;
//! println!("{:?} last ran {:?}", job.command_line(), job.last_run);
//! # Ok(())
//! # }
//! ```
//!
//! Damage is reported in `problems`, never a panic.

pub mod job;
pub mod task;
mod xml;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A kind of task file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A task XML file.
    Xml,
    /// A `.job` file.
    Job,
}

/// Which kind of task file `head` starts like, if any.
#[must_use]
pub fn detect(head: &[u8]) -> Option<Kind> {
    if job::detect(head) {
        Some(Kind::Job)
    } else if task::detect(head) {
        Some(Kind::Xml)
    } else {
        None
    }
}
