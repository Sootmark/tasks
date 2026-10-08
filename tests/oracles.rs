//! The task XML files of Atomic Red Team (MIT) and one written for these
//! tests, read as Python's own XML parser reads them
//! (`tests/oracle/tasks.tsv`), and plaso's `.job` file (Apache-2.0) read as
//! plaso reads it (`tests/oracle/plaso.tsv`); see `tests/oracle/README`.

use std::io::Read;

use common::time::Ts;
use tasks::task::{Action, Task};
use tasks::Kind;

fn fixture(path: &str) -> Vec<u8> {
    let raw = std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(raw.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// A task's values as the oracle names them.
fn rows(name: &str, task: &Task) -> Vec<String> {
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut add = |key: String, value: Option<&str>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            rows.push((key, value.replace(['\r', '\n'], " ")));
        }
    };
    add("URI".into(), task.uri.as_deref());
    add("Author".into(), task.author.as_deref());
    add("Description".into(), task.description.as_deref());
    add("Date".into(), task.date.as_deref());
    for (index, trigger) in task.triggers.iter().enumerate() {
        let key = |name: &str| format!("trigger{index}.{name}");
        add(key("kind"), Some(&trigger.kind));
        add(
            key("enabled"),
            Some(if trigger.enabled { "true" } else { "false" }),
        );
        add(key("StartBoundary"), trigger.start.as_deref());
        add(key("EndBoundary"), trigger.end.as_deref());
        add(key("UserId"), trigger.user_id.as_deref());
        add(key("Subscription"), trigger.subscription.as_deref());
        add(key("Repetition"), trigger.repetition.as_deref());
    }
    for (index, principal) in task.principals.iter().enumerate() {
        let key = |name: &str| format!("principal{index}.{name}");
        add(key("id"), principal.id.as_deref());
        add(key("UserId"), principal.user_id.as_deref());
        add(key("GroupId"), principal.group_id.as_deref());
        add(key("LogonType"), principal.logon_type.as_deref());
        add(key("RunLevel"), principal.run_level.as_deref());
    }
    add(
        "enabled".into(),
        Some(if task.enabled() { "true" } else { "false" }),
    );
    add(
        "hidden".into(),
        Some(if task.hidden() { "true" } else { "false" }),
    );
    add("context".into(), task.context.as_deref());
    for (index, action) in task.actions.iter().enumerate() {
        add(format!("action{index}"), Some(&action.summary()));
        if let Action::Exec {
            working_directory, ..
        } = action
        {
            add(
                format!("action{index}.WorkingDirectory"),
                working_directory.as_deref(),
            );
        }
    }
    rows.into_iter()
        .map(|(key, value)| format!("{name}\t{key}\t{value}"))
        .collect()
}

#[test]
fn task_xml_as_python_reads_it() {
    let mut got = Vec::new();
    for path in [
        "atomic/T1053_005_WMI.xml.gz",
        "atomic/T1053_05_SCTASK_HIDDEN_ATTRIB.xml.gz",
        "written/OneDriveSync.gz",
    ] {
        let data = fixture(path);
        assert_eq!(tasks::detect(&data[..200]), Some(Kind::Xml), "{path}");
        let task = tasks::task::read(&data);
        assert_eq!(task.problems, Vec::<String>::new(), "{path}");
        let name = path.rsplit('/').next().unwrap().trim_end_matches(".gz");
        got.extend(rows(name, &task));
    }
    got.sort();
    let mut expected: Vec<&str> = include_str!("oracle/tasks.tsv").lines().collect();
    expected.sort_unstable();
    assert_eq!(got, expected);
}

/// Microseconds since 1970 of a wall clock, as plaso shows a local time.
fn micros(time: Option<Ts>) -> String {
    time.and_then(|t| t.ticks())
        .map_or_else(String::new, |ticks| (ticks / 10).to_string())
}

#[test]
fn job_as_plaso_reads_it() {
    let data = fixture("plaso/wintask.job.gz");
    assert_eq!(tasks::detect(&data), Some(Kind::Job));
    let job = tasks::job::read(&data).unwrap();
    assert_eq!(job.problems, Vec::<String>::new());
    let trigger = &job.triggers[0];
    let got = [
        ("Last Time Executed", micros(job.last_run)),
        ("Scheduled to start", micros(trigger.start)),
        ("application", job.application.clone().unwrap_or_default()),
        ("parameters", job.parameters.clone().unwrap_or_default()),
        ("username", job.author.clone().unwrap_or_default()),
        ("trigger_type", trigger.kind.to_string()),
        ("comment", job.comment.clone().unwrap_or_default()),
    ]
    .map(|(key, value)| format!("wintask.job\t{key}\t{value}"));
    let expected: Vec<&str> = include_str!("oracle/plaso.tsv").lines().collect();
    assert_eq!(got.to_vec(), expected);
}

#[test]
fn beyond_the_oracles() {
    let job = tasks::job::read(&fixture("plaso/wintask.job.gz")).unwrap();
    assert_eq!(job.status_name(), Some("SCHED_S_TASK_READY"));
    assert_eq!(job.triggers.len(), 1);
    assert_eq!(
        (job.triggers[0].kind_name(), job.triggers[0].interval),
        ("DAILY", 60)
    );
    assert!(!job.disabled());
    assert_eq!(
        job.command_line().as_deref(),
        Some(r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua /installsource scheduler")
    );
    let task = tasks::task::read(&fixture("written/OneDriveSync.gz"));
    assert_eq!(
        task.registered().and_then(|t| t.to_iso8601()).as_deref(),
        Some("2024-03-05T09:14:22.4581234")
    );
    assert_eq!(
        task.triggers[0]
            .start_time()
            .and_then(|t| t.to_iso8601())
            .as_deref(),
        Some("2024-03-05T09:30:00.0000000Z")
    );
    assert_eq!(task.setting("IdleSettings.StopOnIdleEnd"), Some("true"));
    assert_eq!(
        task.triggers[0].details,
        [("ScheduleByDay.DaysInterval".to_owned(), "1".to_owned())]
    );
    assert_eq!(
        task.principal().and_then(|p| p.run_level.as_deref()),
        Some("HighestAvailable")
    );
}
