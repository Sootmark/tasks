//! Task XML files (`Windows\System32\Tasks\<folder>\<name>`, no extension;
//! what `schtasks /query /xml` prints), as the Task Scheduler schema
//! defines them: the registration (author, date, URI, description), the
//! triggers, the principals (account, group, logon type, run level), the
//! settings (enabled, hidden, …) and the actions (programs run, COM
//! handlers, e-mails, messages).
//!
//! Text in UTF-16 (as Windows writes it) or UTF-8, byte order marks
//! honoured. Times as written: local unless they carry `Z` or an offset.

use common::time::{days_from_civil, Precision, Ts};

use crate::xml::{self, Element};

/// The ticks of a second.
const TICKS_PER_SECOND: i64 = 10_000_000;

/// A task.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Task {
    /// Where it is in the Task Scheduler's tree (`\Microsoft\Windows\…`).
    pub uri: Option<String>,
    /// Who registered it, as written (an account, a SID, or a resource
    /// string such as `$(@%SystemRoot%\system32\…,-600)`).
    pub author: Option<String>,
    /// Its description.
    pub description: Option<String>,
    /// When it was registered, as written.
    pub date: Option<String>,
    /// Its source and version, as written.
    pub source: Option<String>,
    /// Its version, as written.
    pub version: Option<String>,
    /// When it should run.
    pub triggers: Vec<Trigger>,
    /// Whom it runs as.
    pub principals: Vec<Principal>,
    /// Its settings, nested ones dotted (`IdleSettings.StopOnIdleEnd`), as
    /// written.
    pub settings: Vec<(String, String)>,
    /// The principal the actions run as (`Context`).
    pub context: Option<String>,
    /// What it does.
    pub actions: Vec<Action>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl Task {
    /// A setting by name (`Hidden`, `IdleSettings.StopOnIdleEnd`).
    #[must_use]
    pub fn setting(&self, name: &str) -> Option<&str> {
        self.settings
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Whether the task is enabled (`Enabled`, true by default).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.setting("Enabled") != Some("false")
    }

    /// Whether the task is hidden from the user interface (`Hidden`).
    #[must_use]
    pub fn hidden(&self) -> bool {
        self.setting("Hidden") == Some("true")
    }

    /// When it was registered: the date as a time.
    #[must_use]
    pub fn registered(&self) -> Option<Ts> {
        self.date.as_deref().and_then(parse_time)
    }

    /// The principal the actions run as: the one `Context` names, or the
    /// only one.
    #[must_use]
    pub fn principal(&self) -> Option<&Principal> {
        match &self.context {
            Some(id) => self.principals.iter().find(|p| p.id.as_ref() == Some(id)),
            None => self.principals.first(),
        }
    }
}

/// When a task runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trigger {
    /// The trigger's element without `Trigger` (`Logon`, `Boot`, `Time`,
    /// `Calendar`, `Event`, `Idle`, `Registration`,
    /// `SessionStateChange`).
    pub kind: String,
    /// Whether it is enabled (true by default).
    pub enabled: bool,
    /// When it starts being active (`StartBoundary`), as written.
    pub start: Option<String>,
    /// When it stops (`EndBoundary`), as written.
    pub end: Option<String>,
    /// The account it waits for (logon and session triggers).
    pub user_id: Option<String>,
    /// How often it repeats (`Repetition/Interval`, `PT5M`).
    pub repetition: Option<String>,
    /// The event query an event trigger waits for (`Subscription`).
    pub subscription: Option<String>,
    /// Its other values, nested ones dotted (`ScheduleByDay.DaysInterval`),
    /// as written.
    pub details: Vec<(String, String)>,
}

impl Trigger {
    /// `start` as a time.
    #[must_use]
    pub fn start_time(&self) -> Option<Ts> {
        self.start.as_deref().and_then(parse_time)
    }
}

/// An account a task runs as.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Principal {
    /// Its id, which `Context` names.
    pub id: Option<String>,
    /// The account (`S-1-5-18`, `NT AUTHORITY\SYSTEM`, `DOMAIN\user`).
    pub user_id: Option<String>,
    /// The group, for a task run by any member (`S-1-5-32-545`).
    pub group_id: Option<String>,
    /// How it logs on (`InteractiveToken`, `Password`, `S4U`,
    /// `ServiceAccount`, …).
    pub logon_type: Option<String>,
    /// `HighestAvailable` (elevated) or `LeastPrivilege`.
    pub run_level: Option<String>,
}

/// What a task does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Runs a program.
    Exec {
        /// The program, as written (environment variables kept).
        command: String,
        /// Its arguments.
        arguments: Option<String>,
        /// Its working directory.
        working_directory: Option<String>,
    },
    /// Loads a COM object.
    ComHandler {
        /// Its class identifier.
        class_id: String,
        /// The data passed to it.
        data: Option<String>,
    },
    /// Sends an e-mail (deprecated, still read).
    SendEmail {
        /// The recipient.
        to: Option<String>,
        /// The subject.
        subject: Option<String>,
    },
    /// Shows a message (deprecated, still read).
    ShowMessage {
        /// The title.
        title: Option<String>,
        /// The body.
        body: Option<String>,
    },
}

impl Action {
    /// What runs, as one line: a command line, a COM class, an e-mail or a
    /// message.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Exec {
                command, arguments, ..
            } => match arguments {
                Some(arguments) => format!("{command} {arguments}"),
                None => command.clone(),
            },
            Self::ComHandler { class_id, data } => match data {
                Some(data) => format!("COM {class_id} ({data})"),
                None => format!("COM {class_id}"),
            },
            Self::SendEmail { to, subject } => format!(
                "e-mail to {}: {}",
                to.as_deref().unwrap_or("?"),
                subject.as_deref().unwrap_or("")
            ),
            Self::ShowMessage { title, body } => format!(
                "message {}: {}",
                title.as_deref().unwrap_or(""),
                body.as_deref().unwrap_or("")
            ),
        }
    }
}

/// Whether `head` starts like a task XML file: a `<Task` element in its
/// first bytes, in UTF-8 or UTF-16.
#[must_use]
pub fn detect(head: &[u8]) -> bool {
    let text = decode(&head[..head.len().min(1024) & !1]);
    text.contains("<Task ") || text.contains("<Task>")
}

/// Read a task XML file.
#[must_use]
pub fn read(data: &[u8]) -> Task {
    let text = decode(data);
    let (root, problems) = xml::parse(&text);
    let mut task = Task {
        problems,
        ..Task::default()
    };
    let Some(root) = root.filter(|r| r.name == "Task") else {
        task.problems.push("no <Task> element".to_owned());
        return task;
    };
    if let Some(info) = root.child("RegistrationInfo") {
        let text = |name| info.child_text(name).map(str::to_owned);
        task.uri = text("URI");
        task.author = text("Author");
        task.description = text("Description");
        task.date = text("Date");
        task.source = text("Source");
        task.version = text("Version");
    }
    if let Some(triggers) = root.child("Triggers") {
        task.triggers = triggers.children.iter().map(trigger).collect();
    }
    if let Some(principals) = root.child("Principals") {
        task.principals = principals.children.iter().map(principal).collect();
    }
    if let Some(settings) = root.child("Settings") {
        flatten(settings, "", &mut task.settings);
    }
    if let Some(actions) = root.child("Actions") {
        task.context = actions.attribute("Context").map(str::to_owned);
        for element in &actions.children {
            match action(element) {
                Some(action) => task.actions.push(action),
                None => task
                    .problems
                    .push(format!("an action <{}> not read", element.name)),
            }
        }
    }
    task
}

fn trigger(element: &Element) -> Trigger {
    let text = |name| element.child_text(name).map(str::to_owned);
    let mut details = Vec::new();
    for child in &element.children {
        if ![
            "Enabled",
            "StartBoundary",
            "EndBoundary",
            "UserId",
            "Repetition",
            "Subscription",
        ]
        .contains(&child.name.as_str())
        {
            flatten_one(child, "", &mut details);
        }
    }
    Trigger {
        kind: element
            .name
            .strip_suffix("Trigger")
            .unwrap_or(&element.name)
            .to_owned(),
        enabled: element.child_text("Enabled") != Some("false"),
        start: text("StartBoundary"),
        end: text("EndBoundary"),
        user_id: text("UserId"),
        repetition: element
            .child("Repetition")
            .and_then(|r| r.child_text("Interval"))
            .map(str::to_owned),
        subscription: text("Subscription"),
        details,
    }
}

fn principal(element: &Element) -> Principal {
    let text = |name| element.child_text(name).map(str::to_owned);
    Principal {
        id: element.attribute("id").map(str::to_owned),
        user_id: text("UserId"),
        group_id: text("GroupId"),
        logon_type: text("LogonType"),
        run_level: text("RunLevel"),
    }
}

fn action(element: &Element) -> Option<Action> {
    let text = |name| element.child_text(name).map(str::to_owned);
    Some(match element.name.as_str() {
        "Exec" => Action::Exec {
            command: text("Command")?,
            arguments: text("Arguments"),
            working_directory: text("WorkingDirectory"),
        },
        "ComHandler" => Action::ComHandler {
            class_id: text("ClassId")?,
            data: text("Data"),
        },
        "SendEmail" => Action::SendEmail {
            to: text("To"),
            subject: text("Subject"),
        },
        "ShowMessage" => Action::ShowMessage {
            title: text("Title"),
            body: text("Body"),
        },
        _ => return None,
    })
}

/// Every child's text, nested ones dotted under their parent's name.
fn flatten(element: &Element, prefix: &str, into: &mut Vec<(String, String)>) {
    for child in &element.children {
        flatten_one(child, prefix, into);
    }
}

fn flatten_one(element: &Element, prefix: &str, into: &mut Vec<(String, String)>) {
    let name = format!("{prefix}{}", element.name);
    if element.children.is_empty() {
        into.push((name, element.text.clone()));
    } else {
        flatten(element, &format!("{name}."), into);
    }
}

/// Text in UTF-16 (byte order mark, or zero bytes giving it away) or UTF-8.
fn decode(data: &[u8]) -> String {
    let utf16 = |data: &[u8], big: bool| {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|p| {
                if big {
                    u16::from_be_bytes([p[0], p[1]])
                } else {
                    u16::from_le_bytes([p[0], p[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match data {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [b'<', 0, ..] => utf16(data, false),
        [0, b'<', ..] => utf16(data, true),
        _ => String::from_utf8_lossy(data).into_owned(),
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction][Z|±HH:MM]`: UTC with `Z` or an offset,
/// local without.
fn parse_time(text: &str) -> Option<Ts> {
    let text = text.trim();
    let (date, time) = text.split_once('T')?;
    let mut parts = date.splitn(3, '-');
    let year: i64 = parts
        .next()?
        .parse()
        .ok()
        .filter(|y| (1..=9999).contains(y))?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let (clock, zone) = match time.find(['Z', '+', '-']) {
        Some(at) => (&time[..at], Some(&time[at..])),
        None => (time, None),
    };
    let (whole, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let mut fields = whole.splitn(3, ':');
    let hour: i64 = fields.next()?.parse().ok()?;
    let minute: i64 = fields.next()?.parse().ok()?;
    let second: i64 = fields.next().unwrap_or("0").parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let digits: String = fraction.chars().take(7).collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let sub: i64 = format!("{digits:0<7}").parse().ok()?;
    let ticks = ((days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
        * TICKS_PER_SECOND)
        + sub;
    let precision = if digits.is_empty() {
        Precision::Second
    } else {
        Precision::Tick
    };
    match zone {
        None => Some(Ts::from_local_ticks(ticks, precision)),
        Some("Z") => Some(Ts::from_ticks(ticks, precision)),
        Some(offset) => {
            let sign = if offset.starts_with('-') { -1 } else { 1 };
            let (hours, minutes) = offset[1..].split_once(':').unwrap_or((&offset[1..], "0"));
            let minutes = hours.parse::<i32>().ok()? * 60 + minutes.parse::<i32>().ok()?;
            Some(Ts::from_local_ticks(ticks, precision).assume_offset(sign * minutes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let iso = |t: &str| parse_time(t).and_then(|t| t.to_iso8601());
        assert_eq!(
            iso("2021-04-22T12:29:17").as_deref(),
            Some("2021-04-22T12:29:17.0000000")
        );
        assert_eq!(
            iso("2021-04-22T12:29:17Z").as_deref(),
            Some("2021-04-22T12:29:17.0000000Z")
        );
        assert_eq!(
            iso("2021-04-22T12:29:17.5+02:00").as_deref(),
            Some("2021-04-22T10:29:17.5000000Z")
        );
        assert_eq!(iso("2021-13-22T12:29:17"), None);
        assert_eq!(iso("yesterday"), None);
    }

    #[test]
    fn com_handlers_event_triggers_and_defaults() {
        let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><EventTrigger><Subscription>&lt;QueryList&gt;&lt;/QueryList&gt;</Subscription><Delay>PT1M</Delay></EventTrigger><TimeTrigger><Enabled>false</Enabled><Repetition><Interval>PT5M</Interval></Repetition></TimeTrigger></Triggers><Actions Context="LocalSystem"><ComHandler><ClassId>{A6BA00FE-40E8-477C-B713-C64A14F18ADB}</ClassId></ComHandler></Actions><Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals></Task>"#;
        let task = read(xml.as_bytes());
        assert!(task.problems.is_empty(), "{:?}", task.problems);
        assert!(task.enabled() && !task.hidden());
        assert_eq!(task.triggers[0].kind, "Event");
        assert_eq!(
            task.triggers[0].subscription.as_deref(),
            Some("<QueryList></QueryList>")
        );
        assert_eq!(
            task.triggers[0].details,
            [("Delay".to_owned(), "PT1M".to_owned())]
        );
        assert!(!task.triggers[1].enabled);
        assert_eq!(task.triggers[1].repetition.as_deref(), Some("PT5M"));
        assert_eq!(
            task.actions[0].summary(),
            "COM {A6BA00FE-40E8-477C-B713-C64A14F18ADB}"
        );
        assert_eq!(
            task.principal().and_then(|p| p.user_id.as_deref()),
            Some("S-1-5-18")
        );
    }

    #[test]
    fn other_files() {
        assert!(!detect(b"<plist>"));
        assert_eq!(read(b"<plist/>").problems, ["no <Task> element"]);
        assert_eq!(read(b"").problems, ["no <Task> element"]);
    }
}
