//! Watches the PBS config file for a change to its contents.

use std::path::Path;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::warn;

/// Calls `on_change` each time the contents of `path` differ from the last
/// ones it accepted, so a failed reload is retried at the next event. Watches
/// the directory too, since replacing the file ends the watch on it
pub(crate) fn watch(
    path: &Path,
    on_change: impl Fn() -> bool + Send + 'static,
) -> notify::Result<RecommendedWatcher> {
    let file = path.to_path_buf();
    let mut accepted = std::fs::read(&file).ok();
    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<Event>| match result {
            Ok(event) => handle(&event, &file, &mut accepted, &on_change),
            Err(err) => warn!(%err, "error watching PBS config file for changes"),
        },
        notify::Config::default(),
    )?;
    // A write to a bind-mounted file shows only on the file itself
    watcher.watch(path, RecursiveMode::NonRecursive)?;
    // A bare file name has an empty parent
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if let Err(err) = watcher.watch(dir, RecursiveMode::NonRecursive) {
        warn!(%err, ?dir, "cannot watch the PBS config file's directory, so a replaced file is not seen");
    }
    Ok(watcher)
}

/// Calls `on_change` when `event` can have changed the file and it reads
/// differently from `accepted`, which a successful reload updates
fn handle(
    event: &Event,
    file: &Path,
    accepted: &mut Option<Vec<u8>>,
    on_change: &dyn Fn() -> bool,
) {
    // Reading the file opens it, so acting on an open or read would loop
    if event.kind.is_access() {
        return;
    }
    // Missing mid-replace; the event that completes the replace reads it
    let Ok(contents) = std::fs::read(file) else { return };
    if accepted.as_ref() != Some(&contents) && on_change() {
        *accepted = Some(contents);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use notify::event::{AccessKind, AccessMode, EventKind, ModifyKind};

    use super::*;

    fn counted(path: &Path) -> (RecommendedWatcher, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let watcher = watch(path, move || {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        })
        .unwrap();
        (watcher, count)
    }

    /// Waits up to 5 s for `count` to reach `want`, then 300 ms for any extra
    /// call
    fn settled(count: &AtomicUsize, want: usize) -> usize {
        let start = Instant::now();
        while count.load(Ordering::SeqCst) < want && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(300));
        count.load(Ordering::SeqCst)
    }

    // A ConfigMap mount: the file is a symlink through `..data`, which an
    // update points at a new directory
    #[cfg(unix)]
    #[test]
    fn every_configmap_update_is_seen() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let version = |name: &str, contents: &str| -> PathBuf {
            let path = dir.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("config.toml"), contents).unwrap();
            path
        };
        version("..v1", "a = 1");
        symlink("..v1", dir.path().join("..data")).unwrap();
        symlink("..data/config.toml", dir.path().join("config.toml")).unwrap();
        let (_watcher, count) = counted(&dir.path().join("config.toml"));

        for (n, (name, old)) in [("..v2", "..v1"), ("..v3", "..v2")].into_iter().enumerate() {
            version(name, &format!("a = {}", n + 2));
            symlink(name, dir.path().join("..data_tmp")).unwrap();
            fs::rename(dir.path().join("..data_tmp"), dir.path().join("..data")).unwrap();
            fs::remove_dir_all(dir.path().join(old)).unwrap();
            assert_eq!(settled(&count, n + 1), n + 1, "update {}", n + 1);
        }
    }

    #[test]
    fn every_replace_by_rename_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "a = 1").unwrap();
        let (_watcher, count) = counted(&path);

        for n in 1..=2 {
            let tmp = dir.path().join("config.toml.tmp");
            fs::write(&tmp, format!("a = {}", n + 1)).unwrap();
            fs::rename(&tmp, &path).unwrap();
            assert_eq!(settled(&count, n), n, "replace {n}");
        }
    }

    #[test]
    fn a_write_in_place_is_seen_and_a_chmod_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "a = 1").unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (file, reads) = (path.clone(), seen.clone());
        let _watcher = watch(&path, move || {
            reads.lock().unwrap().push(fs::read_to_string(&file).unwrap_or_default());
            true
        })
        .unwrap();
        let last = || seen.lock().unwrap().last().cloned();

        fs::write(&path, "a = 2").unwrap();
        // A read can land mid-write, so wait for the final contents
        let start = Instant::now();
        while last().as_deref() != Some("a = 2") && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(last().as_deref(), Some("a = 2"));

        // The write's own events can still be arriving
        thread::sleep(Duration::from_millis(500));
        let calls = seen.lock().unwrap().len();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(seen.lock().unwrap().len(), calls);
    }

    // A write through another link to the file reaches only the file's own
    // watch, as a host write to a bind-mounted file does
    #[cfg(unix)]
    #[test]
    fn a_write_through_another_link_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("a")).unwrap();
        fs::create_dir(dir.path().join("b")).unwrap();
        let path = dir.path().join("a/config.toml");
        fs::write(&path, "a = 1").unwrap();
        fs::hard_link(&path, dir.path().join("b/config.toml")).unwrap();
        let (_watcher, count) = counted(&path);

        fs::write(dir.path().join("b/config.toml"), "a = 2").unwrap();
        assert!(settled(&count, 1) >= 1);
    }

    // An open or a read is not a change, since reading the file is one; a
    // write is
    #[test]
    fn only_a_change_to_the_file_is_handled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "a = 2").unwrap();
        let mut accepted = Some(b"a = 1".to_vec());
        let calls = AtomicUsize::new(0);
        let on_change = || {
            calls.fetch_add(1, Ordering::SeqCst);
            true
        };
        for kind in [
            AccessKind::Open(AccessMode::Any),
            AccessKind::Read,
            AccessKind::Close(AccessMode::Read),
        ] {
            handle(&Event::new(EventKind::Access(kind)), &path, &mut accepted, &on_change);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        handle(&Event::new(EventKind::Modify(ModifyKind::Any)), &path, &mut accepted, &on_change);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // A reload that fails leaves the contents unaccepted, so the next event
    // retries it, and one that succeeds is not repeated
    #[test]
    fn a_failed_reload_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "a = 2").unwrap();
        let mut accepted = Some(b"a = 1".to_vec());
        let calls = AtomicUsize::new(0);
        let on_change = || calls.fetch_add(1, Ordering::SeqCst) > 0;
        let modified = Event::new(EventKind::Modify(ModifyKind::Any));
        for _ in 0..3 {
            handle(&modified, &path, &mut accepted, &on_change);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(accepted.as_deref(), Some(&b"a = 2"[..]));
    }

    // A directory the service can enter but not list still lets it watch the
    // file
    #[cfg(unix)]
    #[test]
    fn an_unlistable_directory_still_watches_the_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "a = 1").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o311)).unwrap();
        let watched = watch(&path, || true);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(watched.is_ok(), "{:?}", watched.err());
    }
}
