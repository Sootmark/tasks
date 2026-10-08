//! `.job` files (`Windows\Tasks\*.job`: Windows XP and 2003 tasks, and
//! what `at` and older installers still write on later Windows), as
//! MS-TSCH defines them: a fixed-length part (the job's identifier, its
//! priority and maximum run time, its status and exit code, its flags and
//! when it last ran), then the program, its parameters, working directory,
//! author and comment, and the triggers.
//!
//! Times are local, their zone not recorded.

use common::time::{days_from_civil, Precision, Ts};

/// The ticks of a second.
const TICKS_PER_SECOND: i64 = 10_000_000;
/// The fixed-length part's size.
const FIXED: usize = 68;
/// A trigger's size.
const TRIGGER: usize = 48;

/// A job.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Job {
    /// Its identifier (a GUID).
    pub id: String,
    /// The program run.
    pub application: Option<String>,
    /// Its parameters.
    pub parameters: Option<String>,
    /// Its working directory.
    pub working_directory: Option<String>,
    /// Who created it.
    pub author: Option<String>,
    /// Its comment.
    pub comment: Option<String>,
    /// Its priority class (`0x20` normal, `0x40` idle, `0x80` high,
    /// `0x100` real time).
    pub priority: u32,
    /// The longest it may run, in milliseconds (`0xFFFFFFFF`: no limit).
    pub max_run_time: u32,
    /// The last run's exit code.
    pub exit_code: u32,
    /// Its status (`0x41300` ready, `0x41301` running, `0x41303` has not
    /// run, …; see [`Job::status_name`]).
    pub status: u32,
    /// Its flags (`0x4` disabled, `0x200` hidden, …).
    pub flags: u32,
    /// When it last ran (local time), `None` if never.
    pub last_run: Option<Ts>,
    /// When it runs.
    pub triggers: Vec<JobTrigger>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl Job {
    /// Whether the job is disabled (`TASK_FLAG_DISABLED`).
    #[must_use]
    pub const fn disabled(&self) -> bool {
        self.flags & 0x4 != 0
    }

    /// Whether the job is hidden (`TASK_FLAG_HIDDEN`).
    #[must_use]
    pub const fn hidden(&self) -> bool {
        self.flags & 0x200 != 0
    }

    /// The status's name (`SCHED_S_TASK_READY`, …).
    #[must_use]
    pub const fn status_name(&self) -> Option<&'static str> {
        Some(match self.status {
            0x0004_1300 => "SCHED_S_TASK_READY",
            0x0004_1301 => "SCHED_S_TASK_RUNNING",
            0x0004_1302 => "SCHED_S_TASK_DISABLED",
            0x0004_1303 => "SCHED_S_TASK_HAS_NOT_RUN",
            0x0004_1304 => "SCHED_S_TASK_NO_MORE_RUNS",
            0x0004_1305 => "SCHED_S_TASK_NOT_SCHEDULED",
            0x0004_1306 => "SCHED_S_TASK_TERMINATED",
            0x0004_1307 => "SCHED_S_TASK_NO_VALID_TRIGGERS",
            _ => return None,
        })
    }

    /// The command line run: the program and its parameters.
    #[must_use]
    pub fn command_line(&self) -> Option<String> {
        let application = self.application.as_deref()?;
        Some(match self.parameters.as_deref() {
            Some(parameters) => format!("{application} {parameters}"),
            None => application.to_owned(),
        })
    }
}

/// When a job runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobTrigger {
    /// Its type: 0 once, 1 daily, 2 weekly, 3 monthly by date, 4 monthly
    /// by day of week, 5 when idle, 6 at system start, 7 at logon.
    pub kind: u32,
    /// When it starts (local time): its first day at its start time.
    pub start: Option<Ts>,
    /// Its last day (local time), if it has one.
    pub end: Option<Ts>,
    /// How long it repeats for, in minutes.
    pub duration: u32,
    /// How often it repeats within that, in minutes.
    pub interval: u32,
    /// Its flags (`0x4` disabled, …).
    pub flags: u32,
}

impl JobTrigger {
    /// The type's name, as MS-TSCH calls it (`DAILY`, `EVENT_AT_LOGON`).
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            0 => "ONCE",
            1 => "DAILY",
            2 => "WEEKLY",
            3 => "MONTHLYDATE",
            4 => "MONTHLYDOW",
            5 => "EVENT_ON_IDLE",
            6 => "EVENT_AT_SYSTEMSTART",
            7 => "EVENT_AT_LOGON",
            _ => "UNKNOWN",
        }
    }
}

/// Why a file can't be read as a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Whether `head` starts like a `.job` file: file version 1, the program's
/// name right after the fixed-length part, the triggers after it, and a
/// plausible priority.
#[must_use]
pub fn detect(head: &[u8]) -> bool {
    let word = |at| u16_at(head, at).map(usize::from);
    word(2) == Some(1)
        && word(20) == Some(FIXED + 2)
        && word(22).is_some_and(|t| t > FIXED + 2)
        && u32_at(head, 32).is_some_and(|p| matches!(p, 0x20 | 0x40 | 0x80 | 0x100))
}

/// Read a `.job` file.
///
/// # Errors
/// When it doesn't start like one.
pub fn read(data: &[u8]) -> Result<Job, Error> {
    if data.len() < FIXED + 2 || !detect(data) {
        return Err(Error(
            "not a .job file: no file version 1 and fixed-length part".to_owned(),
        ));
    }
    let u32_of = |at| u32_at(data, at).unwrap_or(0);
    let mut job = Job {
        id: guid(&data[4..20]),
        priority: u32_of(32),
        max_run_time: u32_of(36),
        exit_code: u32_of(40),
        status: u32_of(44),
        flags: u32_of(48),
        last_run: system_time(&data[52..68]),
        ..Job::default()
    };
    let mut at = FIXED + 2;
    let mut strings = [None, None, None, None, None];
    for (index, slot) in strings.iter_mut().enumerate() {
        let Some((text, next)) = string(data, at) else {
            job.problems.push(format!("string {} cut short", index + 1));
            break;
        };
        *slot = Some(text).filter(|t| !t.is_empty());
        at = next;
    }
    let [application, parameters, working_directory, author, comment] = strings;
    job.application = application;
    job.parameters = parameters;
    job.working_directory = working_directory;
    job.author = author;
    job.comment = comment;
    let triggers_at = usize::from(u16_at(data, 22).unwrap_or(0));
    let Some(count) = u16_at(data, triggers_at) else {
        job.problems.push("the triggers past the end".to_owned());
        return Ok(job);
    };
    for index in 0..usize::from(count) {
        let start = triggers_at + 2 + index * TRIGGER;
        let Some(bytes) = data.get(start..start + TRIGGER) else {
            job.problems
                .push(format!("trigger {} cut short", index + 1));
            break;
        };
        job.triggers.push(trigger(bytes));
    }
    Ok(job)
}

fn trigger(bytes: &[u8]) -> JobTrigger {
    let word = |at| i64::from(u16_at(bytes, at).unwrap_or(0));
    let day = |year: i64, month: i64, day: i64| {
        let month = u32::try_from(month).ok().filter(|m| (1..=12).contains(m))?;
        let day = u32::try_from(day).ok().filter(|d| (1..=31).contains(d))?;
        (year > 0).then(|| days_from_civil(year, month, day))
    };
    let start = day(word(4), word(6), word(8))
        .filter(|_| word(16) < 24 && word(18) < 60)
        .map(|days| {
            let seconds = days * 86_400 + word(16) * 3600 + word(18) * 60;
            Ts::from_local_ticks(seconds * TICKS_PER_SECOND, Precision::Second)
        });
    let end = day(word(10), word(12), word(14))
        .map(|days| Ts::from_local_ticks(days * 86_400 * TICKS_PER_SECOND, Precision::Day));
    JobTrigger {
        kind: u32_at(bytes, 32).unwrap_or(0),
        start,
        end,
        duration: u32_at(bytes, 20).unwrap_or(0),
        interval: u32_at(bytes, 24).unwrap_or(0),
        flags: u32_at(bytes, 28).unwrap_or(0),
    }
}

/// A SYSTEMTIME (year, month, day of week, day, hour, minute, second,
/// millisecond) as local time; `None` when all zero or impossible.
fn system_time(bytes: &[u8]) -> Option<Ts> {
    let word = |at| i64::from(u16_at(bytes, at).unwrap_or(0));
    let month = u32::try_from(word(2))
        .ok()
        .filter(|m| (1..=12).contains(m))?;
    let day = u32::try_from(word(6))
        .ok()
        .filter(|d| (1..=31).contains(d))?;
    let (hour, minute, second, millisecond) = (word(8), word(10), word(12), word(14));
    if word(0) == 0 || hour > 23 || minute > 59 || second > 59 || millisecond > 999 {
        return None;
    }
    let seconds =
        days_from_civil(word(0), month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(Ts::from_local_ticks(
        seconds * TICKS_PER_SECOND + millisecond * 10_000,
        Precision::Millisecond,
    ))
}

/// A counted UTF-16 string at `at` (a count of characters, its NUL
/// included, then the characters): the text and where the next starts.
fn string(data: &[u8], at: usize) -> Option<(String, usize)> {
    let count = usize::from(u16_at(data, at)?);
    let bytes = data.get(at + 2..at + 2 + count * 2)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .take_while(|&u| u != 0)
        .collect();
    Some((String::from_utf16_lossy(&units), at + 2 + count * 2))
}

/// A GUID as Windows writes it, upper case.
fn guid(bytes: &[u8]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail = common::sha256::hex(&bytes[8..16]).to_ascii_uppercase();
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{}-{}",
        &tail[..4],
        &tail[4..]
    )
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_times() {
        let mut bytes = [0u8; 16];
        for (i, v) in [2013u16, 8, 6, 24, 12, 42, 0, 112].iter().enumerate() {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        assert_eq!(
            system_time(&bytes).and_then(|t| t.to_iso8601()).as_deref(),
            Some("2013-08-24T12:42:00.1120000")
        );
        assert_eq!(system_time(&[0; 16]), None);
    }

    #[test]
    fn other_files_are_errors() {
        assert!(read(b"not a job").is_err());
        assert!(read(&[0; 100]).is_err());
    }
}
