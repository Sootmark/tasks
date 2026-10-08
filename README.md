# tasks

Windows scheduled tasks, for forensics: the task XML files of `Windows\System32\Tasks` and the `.job` files of `Windows\Tasks`, read into what runs, as whom, when, and whether it is enabled or hidden. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-tasks = "0.1"
```

```rust
let task = tasks::task::read(&std::fs::read(r"C:\Windows\System32\Tasks\Updater")?);
for action in &task.actions {
    println!("{:?} runs {} (hidden: {})", task.uri, action.summary(), task.hidden());
}
```

## What you get

- `detect(head)`: a task XML file or a `.job` file, by content.
- `task::read`: task XML (Vista and later; what `schtasks /query /xml` prints): the registration (URI, author, description, date), each trigger (logon, boot, time, calendar, event with its query, idle, registration, session change; start, end, repetition, user, enabled), the principals (account, group, logon type, run level), every setting (`enabled()`, `hidden()`), and each action (program and arguments, COM handler and data, e-mail, message) with the principal they run as. UTF-16 or UTF-8, byte order marks honoured, the declared encoding not trusted. Times as written: local unless they carry `Z` or an offset.
- `job::read`: `.job` files (XP and 2003, and what `at` and older installers still write), as MS-TSCH defines them: identifier, program, parameters, working directory, author, comment, priority, maximum run time, status, exit code, flags (`disabled()`, `hidden()`), last run, and each trigger with its type, start, end and repetition. Local times.
- Damage goes to `problems`, never a panic; XML nested deeper than 64 levels is skipped.

## How it's checked

- Task XML: Atomic Red Team's two task files (MIT, `tests/fixtures/atomic/`) and one written for these tests (hidden, SYSTEM, elevated, four kinds of trigger, encoded PowerShell, COM handler), every value read as Python's own XML parser reads it (`tests/oracle/tasks.tsv`, written by `tests/oracle/gen.py`).
- `.job`: plaso's test file (Apache-2.0, `tests/fixtures/plaso/`), read as plaso's `winjob` parser reads it: last run, trigger start, program, parameters, author, comment, trigger type. Beyond plaso: status, flags, repetition.
- Property tests: arbitrary and damaged files give a result, problems or an error, never a panic.

## Licence

MIT or Apache-2.0, at your option.
