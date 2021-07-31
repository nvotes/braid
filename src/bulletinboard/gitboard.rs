// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};

use git2::build::{CheckoutBuilder, RepoBuilder};
use git2::*;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

use crate::bulletinboard::board::Board;
use crate::bulletinboard::mixnetboard::BBError;
use crate::util;

#[derive(Serialize, Deserialize)]
pub struct GitBoard {
    pub ssh_key_path: String,
    pub url: String,
    pub fs_path: String,
    pub append_only: bool,
    pub auto_push: bool,
}

impl Board for GitBoard {
    fn list(&self) -> Result<Vec<String>, BBError> {
        self.list_entries()
    }
    fn get(&self, target: String) -> Result<Option<Vec<u8>>, BBError> {
        self.get_bytes(Path::new(&target))
    }
    fn add(&mut self, entries: Vec<(&Path, Vec<u8>)>, message: String) -> Result<(), BBError> {
        self.add_and_commit(entries, &message)?;
        if self.auto_push {
            self.post()?;
        }
        Ok(())
    }

    fn post(&self) -> Result<(), BBError> {
        let repo = self.open()?;
        self.push(&repo).map_err(BBError::from)
    }
    fn get_unsafe(&self, target: &str) -> Result<Option<Vec<u8>>, BBError> {
        let target_file = Path::new(&self.fs_path).join(target);
        if target_file.exists() {
            let bytes = util::read_file_bytes(&target_file)?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }
    /* fn get_config_type(&self, target: &str) -> Option<bool> {
        let bytes = self.data.get(target)?;
        // let config_rug = bincode::deserialize::<Config<Integer, RugGroup>>(bytes);
        let config_rug = Config::<Integer, RugGroup>::deser(bytes);

        // let config_ristretto = bincode::deserialize::<Config<RistrettoPoint, RistrettoGroup>>(bytes);
        let config_ristretto = Config::<RistrettoPoint, RistrettoGroup>::deser(bytes);
        if config_rug.is_ok() {
            Some(true)
        }
        else if config_ristretto.is_ok() {
            Some(false)
        }
        else {
            None
        }
    }*/
}

impl GitBoard {
    fn open_or_clone(&self) -> Result<Repository, Error> {
        if Path::new(&self.fs_path).exists() {
            self.open()
        } else {
            self.clone_repo()
        }
    }

    pub fn open(&self) -> Result<Repository, Error> {
        info!("GIT {}: open..", self.fs_path);
        Repository::open(&self.fs_path)
    }

    pub fn clone_repo(&self) -> Result<Repository, Error> {
        info!("GIT {}: clone..", self.fs_path);
        let now = std::time::Instant::now();
        let co = CheckoutBuilder::new();
        let mut fo = FetchOptions::new();
        let cb = remote_callbacks(&self.ssh_key_path);
        fo.remote_callbacks(cb);
        let ret = RepoBuilder::new()
            .fetch_options(fo)
            .with_checkout(co)
            .clone(&self.url, Path::new(&self.fs_path));
        info!("GIT clone: [{}ms]", now.elapsed().as_millis());

        ret
    }

    fn list_entries(&self) -> Result<Vec<String>, BBError> {
        let repo = self.open_or_clone()?;
        self.refresh(&repo)?;
        let walker = WalkDir::new(&self.fs_path).min_depth(1).into_iter();
        let entries: Vec<DirEntry> = walker
            .filter_entry(|e| !is_hidden(e))
            .map(|e| e.unwrap())
            .collect();

        // filter directories and make relative
        let files = entries
            .into_iter()
            .filter(|e| !e.file_type().is_dir())
            .map(|e| {
                e.path()
                    .strip_prefix(&self.fs_path)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();

        Ok(files)
    }

    fn get_bytes(&self, target_path: &Path) -> Result<Option<Vec<u8>>, BBError> {
        let target_file = Path::new(&self.fs_path).join(target_path);
        if target_file.exists() {
            let bytes: Vec<u8> = util::read_file_bytes(&target_file)?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    // refreshes the local copy with remote updates
    // preserving local commits (merging if required)
    // uncommitted changes are discarded.
    fn refresh(&self, repo: &Repository) -> Result<bool, Error> {
        info!("GIT {}: refresh..", self.fs_path);
        let now = std::time::Instant::now();
        let mut remote = repo.find_remote("origin").unwrap();

        let mut cb = remote_callbacks(&self.ssh_key_path);
        cb.transfer_progress(|stats| {
            if stats.received_objects() == stats.total_objects() {
                info!(
                    "GIT: Resolving deltas {}/{}\r",
                    stats.indexed_deltas(),
                    stats.total_deltas()
                );
            } else if stats.total_objects() > 0 {
                info!(
                    "GIT: Received {}/{} objects ({}) in {} bytes\r",
                    stats.received_objects(),
                    stats.total_objects(),
                    stats.indexed_objects(),
                    stats.received_bytes()
                );
            }
            true
        });

        let mut fo = FetchOptions::new();
        fo.remote_callbacks(cb);
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;

        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;

        let head = repo.head()?;
        let local_commit = repo.reference_to_annotated_commit(&head)?;
        let local_object = repo.find_object(local_commit.id(), None)?;

        repo.reset(&local_object, git2::ResetType::Hard, None)?;
        let analysis = repo.merge_analysis(&[&commit])?;

        if analysis.0.is_up_to_date() {
            info!("GIT: refresh [{}ms]", now.elapsed().as_millis());
            Ok(true)
        } else if analysis.0.is_fast_forward() {
            info!("GIT: refresh: requires fast forward");
            if self.append_only {
                info!("GIT: append only");
                let mut opts = DiffOptions::new();
                let tree_old = repo.find_commit(local_commit.id()).unwrap().tree().unwrap();
                let tree_new = repo.find_commit(commit.id()).unwrap().tree().unwrap();

                let diff =
                    repo.diff_tree_to_tree(Some(&tree_old), Some(&tree_new), Some(&mut opts))?;
                for d in diff.deltas() {
                    if d.status() != Delta::Added {
                        info!("GIT: append only non-add git delta");
                        return Err(git2::Error::from_str(&format!(
                            "Found non-add git delta in append-only mode: {:?}",
                            d
                        )));
                    }
                }
            }
            let refname = "refs/heads/master".to_string();
            let mut r = repo.find_reference(&refname)?;
            fast_forward(&repo, &mut r, &commit)?;
            info!("GIT refresh ffwd: [{}ms]", now.elapsed().as_millis());
            Ok(true)
        } else {
            warn!("GIT: refresh: merge required");
            let head_commit = repo.reference_to_annotated_commit(&head)?;
            merge(&repo, &head_commit, &commit, "merge", self.append_only)?;
            Ok(true)
        }
    }

    fn add_and_commit(&self, files: Vec<(&Path, Vec<u8>)>, message: &str) -> Result<(), Error> {
        let mut entries = vec![];
        let repo = self.open_or_clone()?;
        for (target, bytes) in files {
            let next = self.prepare_add(target, &bytes);
            entries.push(next);
        }

        add_and_commit(&repo, entries, message, self.append_only)
    }

    fn prepare_add(&self, target_path: &Path, bytes: &[u8]) -> GitAddEntry {
        let target_file = Path::new(&self.fs_path).join(target_path);
        let parent = target_file.parent().unwrap();
        if !parent.exists() {
            info!("GIT: create directory at {:?}", parent);
            fs::create_dir_all(parent).unwrap();
        }

        if target_file.is_file() && target_file.exists() {
            warn!("GIT: file already present at {:?}", target_file);
            fs::remove_file(&target_file).unwrap();
        }
        // FIXME is unwrap ok here
        util::write_file_bytes(&target_file, bytes).unwrap();

        GitAddEntry {
            fs_path: target_file,
            repo_path: target_path.to_path_buf(),
        }
    }

    fn push(&self, repo: &Repository) -> Result<(), Error> {
        let mut options = PushOptions::new();
        options.remote_callbacks(remote_callbacks(&self.ssh_key_path));
        let mut remote = repo.find_remote("origin").unwrap();
        repo.remote_add_push("origin", "refs/heads/master:refs/heads/master")
            .unwrap();
        remote.connect_auth(
            Direction::Push,
            Some(remote_callbacks(&self.ssh_key_path)),
            None,
        )?;
        remote.push(&["refs/heads/master:refs/heads/master"], Some(&mut options))
    }

    // testing only

    // clears the repository index of any files, and pushes
    pub(crate) fn __clear(&self) -> Result<(), Error> {
        let repo = self.open_or_clone()?;
        let mut index = repo.index()?;
        index.clear()?;

        let oid = index.write_tree()?;
        let signature = Signature::now("braid", "braid@foo.bar")?;
        let parent_commit = find_last_commit(&repo)?;
        let tree = repo.find_tree(oid)?;

        index.write()?;
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Reset",
            &tree,
            &[&parent_commit],
        )?;

        self.push(&repo)
    }

    // simulate conflicts (divergent repository)
    fn __add_commit(
        &self,
        repo: &Repository,
        target: &Path,
        source: &[u8],
        message: &str,
        append_only: bool,
    ) -> Result<(), Error> {
        let entry = self.prepare_add(target, source);

        add_and_commit(&repo, vec![entry], message, append_only)
    }
}

struct GitAddEntry {
    fs_path: PathBuf,
    repo_path: PathBuf,
}

fn find_last_commit(repo: &Repository) -> Result<Commit, Error> {
    let obj = repo.head()?.resolve()?.peel(ObjectType::Commit)?;
    match obj.into_commit() {
        Ok(c) => Ok(c),
        _ => Err(git2::Error::from_str("Couldn't find commit")),
    }
}

fn fast_forward(
    repo: &Repository,
    lb: &mut git2::Reference,
    rc: &git2::AnnotatedCommit,
) -> Result<(), Error> {
    let name = match lb.name() {
        Some(s) => s.to_string(),
        None => String::from_utf8_lossy(lb.name_bytes()).to_string(),
    };
    let msg = format!("Fast-Forward: Setting {} to id: {}", name, rc.id());
    lb.set_target(rc.id(), &msg)?;
    repo.set_head(&name)?;
    repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))?;
    Ok(())
}

fn merge(
    repo: &Repository,
    local: &git2::AnnotatedCommit,
    remote: &git2::AnnotatedCommit,
    message: &str,
    append_only: bool,
) -> Result<(), git2::Error> {
    let local_tree = repo.find_commit(local.id())?.tree()?;
    let remote_tree = repo.find_commit(remote.id())?.tree()?;
    let ancestor = repo
        .find_commit(repo.merge_base(local.id(), remote.id())?)?
        .tree()?;
    let mut idx = repo.merge_trees(&ancestor, &local_tree, &remote_tree, None)?;

    if append_only {
        let mut opts = DiffOptions::new();
        let diff = repo.diff_tree_to_index(Some(&local_tree), Some(&idx), Some(&mut opts))?;
        for d in diff.deltas() {
            if d.status() != Delta::Added {
                warn!("GIT: Found non-add git delta during merge in append-only mode");
                return Err(git2::Error::from_str(&format!(
                    "Found non-add git delta during merge in append-only mode: {:?}",
                    d
                )));
            }
        }
    }

    if idx.has_conflicts() {
        error!("Merge conficts detected...");
        return Err(git2::Error::from_str(
            &"Found conflicts during merge attempt".to_string(),
        ));
    }
    let result_tree = repo.find_tree(idx.write_tree_to(repo)?)?;
    // now create the merge commit
    info!("GIT: merge: {} into {}", remote.id(), local.id());

    let signature = Signature::now("braid", "braid@foo.bar")?;
    let local_commit = repo.find_commit(local.id())?;
    let remote_commit = repo.find_commit(remote.id())?;

    // Do our merge commit and set current branch head to that commit.
    let _merge_commit = repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        &message,
        &result_tree,
        &[&local_commit, &remote_commit],
    )?;

    let mut cb = git2::build::CheckoutBuilder::new();
    cb.force();
    // Set working tree to match head.
    repo.checkout_head(Some(&mut cb))?;

    Ok(())
}

fn add_and_commit(
    repo: &Repository,
    entries: Vec<GitAddEntry>,
    message: &str,
    append_only: bool,
) -> Result<(), Error> {
    let mut index = repo.index()?;
    for e in entries {
        info!("GIT add: {:?} ", e.fs_path);
        index.add_path(&e.repo_path)?;
    }
    let oid = index.write_tree()?;
    let signature = Signature::now("braid", "braid@foo.bar")?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;

    if append_only {
        let mut opts = DiffOptions::new();
        let diff =
            repo.diff_tree_to_index(Some(&parent_commit.tree()?), Some(&index), Some(&mut opts))?;
        for d in diff.deltas() {
            if d.status() != Delta::Added {
                warn!("GIT: Found non-add git delta during add in append-only mode");
                return Err(git2::Error::from_str(&format!(
                    "Found non-add git delta during add in append-only mode: {:?}",
                    d
                )));
            }
        }
    }

    index.write()?;
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &[&parent_commit],
    )?;

    Ok(())
}

fn remote_callbacks(ssh_path: &str) -> RemoteCallbacks {
    let mut cb = RemoteCallbacks::new();
    let path = Path::new(ssh_path);
    cb.credentials(move |_, _, _| {
        let credentials =
            Cred::ssh_key("git", None, path, None).expect("Could not create credentials object");

        Ok(credentials)
    });

    cb
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

pub fn test_config() -> GitBoard {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/test/git_bb.json");
    let cfg = fs::read_to_string(d).unwrap();
    let board: GitBoard = serde_json::from_str(&cfg).unwrap();

    board
}

#[cfg(test)]
mod tests {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use serial_test::serial;
    use std::fs;
    use std::path::Path;

    use crate::bulletinboard::gitboard::*;

    fn random_string() -> String {
        let ret: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();

        ret
    }

    #[ignore]
    #[test]
    #[serial]
    fn test_open_or_clone() {
        let g = test_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();

        let dir = Path::new(&g.fs_path);
        assert!(dir.exists() && dir.is_dir());
    }

    #[ignore]
    #[test]
    #[serial]
    fn test_refresh() {
        let g = test_config();

        let dir = Path::new(&g.fs_path);
        assert!(dir.exists() && dir.is_dir());

        g.list().unwrap();
    }

    #[ignore]
    #[test]
    #[serial]
    fn test_post() {
        let g = test_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let name_str = random_string();
        let name = Path::new(&name_str);

        g.add_and_commit(vec![(name, "test".as_bytes().to_vec())], "new file")
            .unwrap();
        g.post().unwrap();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list().unwrap();
        assert!(files.contains(&name.to_str().unwrap().to_string()));
    }

    #[ignore]
    #[test]
    #[serial]
    fn test_append_only() {
        let mut g = test_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();

        // add new file
        let name_str = random_string();
        let name = Path::new(&name_str);
        g.add_and_commit(vec![(name, "test".as_bytes().to_vec())], "new file")
            .unwrap();
        g.post().unwrap();

        // create 2nd repo after creating file but before making modification
        let mut g2 = test_config();
        g2.fs_path.push_str("_");
        fs::remove_dir_all(&g2.fs_path).ok();
        g2.open_or_clone().unwrap();

        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list().unwrap();
        assert!(files.contains(&name.to_str().unwrap().to_string()));

        let result = g.add_and_commit(
            vec![(name, "modified".as_bytes().to_vec())],
            "file modification",
        );
        // cannot modify upstream in append_only mode
        assert!(result.is_err());

        g.append_only = false;
        let result = g.add_and_commit(
            vec![(name, "modified".as_bytes().to_vec())],
            "file modification",
        );
        g.post().unwrap();
        assert!(result.is_ok());

        g2.append_only = true;
        let result = g2.list();
        // cannot modify downstream in append_only mode
        assert!(result.is_err());

        g2.append_only = false;
        let result = g2.list();
        assert!(result.is_ok());
    }

    #[ignore]
    #[test]
    #[serial]
    fn test_clear() {
        let g = test_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        g.__clear().unwrap();

        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list().unwrap();
        assert!(files.len() == 0);
    }

    #[ignore]
    #[test]
    #[serial]
    fn test_divergent() {
        let mut g1 = test_config();
        fs::remove_dir_all(&g1.fs_path).ok();
        g1.open_or_clone().unwrap();

        let mut g2 = test_config();
        g2.fs_path.push_str("_");
        fs::remove_dir_all(&g2.fs_path).ok();
        g2.open_or_clone().unwrap();

        // add new file
        let name_str = random_string();
        let name1 = Path::new(&name_str);
        g1.add_and_commit(vec![(name1, "test".as_bytes().to_vec())], "new file")
            .unwrap();
        g1.post().unwrap();

        // add new file before refresh to trigger a merge
        let name_str = random_string();
        let name = Path::new(&name_str);
        g2.__add_commit(
            &g2.open().unwrap(),
            name,
            &"test".as_bytes().to_vec(),
            "add",
            true,
        )
        .unwrap();
        // will merge
        g2.list().unwrap();

        // modify a file in g1
        g1.append_only = false;
        g1.add_and_commit(
            vec![(name1, "modified".as_bytes().to_vec())],
            "file modification",
        )
        .unwrap();
        g1.post().unwrap();

        // add a new file prior to refreshing to trigger a merge,
        // this time with non-add changes
        let name_str = random_string();
        let name = Path::new(&name_str);
        g2.__add_commit(
            &g2.open().unwrap(),
            name,
            &"test".as_bytes().to_vec(),
            "add",
            true,
        )
        .unwrap();
        // since we are passing false to append only, the merge will work
        g2.append_only = false;
        g2.list().unwrap();

        // modify a file in g1
        g1.append_only = false;
        g1.add_and_commit(
            vec![(name1, "modified again".as_bytes().to_vec())],
            "file modification",
        )
        .unwrap();
        g1.post().unwrap();

        // add a new file prior to refreshing to trigger a merge,
        // this time with non-add changes

        let name_str = random_string();
        let name = Path::new(&name_str);
        g2.__add_commit(
            &g2.open().unwrap(),
            name,
            &"test".as_bytes().to_vec(),
            "add",
            true,
        )
        .unwrap();
        g2.append_only = true;
        let result = g2.list();

        // cannot modify downstream in append_only mode during merge
        assert!(result.is_err());
    }

    #[ignore]
    #[test]
    #[serial]
    pub fn test_git_config() {
        let g1 = test_config();
        fs::remove_dir_all(&g1.fs_path).ok();
        g1.open_or_clone().unwrap();
        let pack_window = "pack.window";
        let cfg_path = Path::new(".git/config");

        let mut cfg = git2::Config::open(&Path::new(&g1.fs_path).join(cfg_path)).unwrap();
        let window = 0;
        cfg.set_i32(&pack_window, window).unwrap();

        for entry in &cfg.entries(None).unwrap() {
            let entry = entry.unwrap();
            println!("{} => {}", entry.name().unwrap(), entry.value().unwrap());
        }
        let window_cfg = cfg.get_i32(&pack_window).unwrap();
        assert_eq!(window, window_cfg);
    }

    #[ignore]
    #[test]
    #[serial]
    pub fn test_git_large() {
        let mut g1 = test_config();
        g1.append_only = false;
        fs::remove_dir_all(&g1.fs_path).ok();
        g1.open_or_clone().unwrap();

        let pack_window = "pack.window";
        let bft = "core.bigFileThreshold";
        let lc = "core.looseCompression";
        let pc = "pack.compression";

        let cfg_path = Path::new(".git/config");

        // seems libgit2 does not support these options
        let mut cfg = git2::Config::open(&Path::new(&g1.fs_path).join(cfg_path)).unwrap();
        let window = 0;
        cfg.set_i32(&pack_window, window).unwrap();
        cfg.set_i32(&bft, 1).unwrap();
        cfg.set_i32(&lc, 0).unwrap();
        cfg.set_i32(&pc, 0).unwrap();

        let cfg = git2::Config::open(&Path::new(&g1.fs_path).join(cfg_path)).unwrap();
        for entry in &cfg.entries(None).unwrap() {
            let entry = entry.unwrap();
            println!("{} => {}", entry.name().unwrap(), entry.value().unwrap());
        }

        let length: usize = 1024 * 1024 * 100;
        println!(">> gen {} bytes..", length);
        let random_bytes = (0..length).map(|_| rand::random::<u8>()).collect();

        g1.add(
            vec![(Path::new("largefile"), random_bytes)],
            String::from("large file"),
        )
        .unwrap();

        println!(">> posting {} bytes..", length);
        let now_ = std::time::Instant::now();
        g1.post().unwrap();
        println!(">> post {}", now_.elapsed().as_millis());
    }
}
