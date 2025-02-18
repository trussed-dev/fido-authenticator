use std::collections::BTreeMap;

use littlefs2_core::{path, DynFilesystem, FileType, Path};

#[derive(Debug, PartialEq)]
pub enum Entry {
    File,
    EmptyDir,
}

#[derive(Debug, Default, PartialEq)]
pub struct Entries(pub BTreeMap<String, Entry>);

impl Entries {
    pub fn remove_standard(&mut self) {
        self.remove_file("fido/sec/00");
        self.remove_file("fido/x5c/00");
        self.remove_file("trussed/dat/rng-state.bin");
    }

    pub fn remove_state(&mut self) {
        self.remove_file("fido/dat/persistent-state.cbor");
    }

    pub fn try_remove_state(&mut self) {
        self.0.remove("fido/dat/persistent-state.cbor");
    }

    pub fn try_remove_keys(&mut self) -> usize {
        self.try_remove_dir("fido/sec")
    }

    pub fn try_remove_rks(&mut self) -> usize {
        let n = self.0.len();
        self.0.retain(|path, _| {
            let (start, _) = path.rsplit_once('/').unwrap();
            let start = start.rsplit_once('/').map(|(start, _)| start);
            start != Some("fido/dat/rk")
        });
        n - self.0.len()
    }

    pub fn try_remove_dir(&mut self, dir: &str) -> usize {
        let n = self.0.len();
        self.0.retain(|path, _| {
            let (start, _) = path.rsplit_once('/').unwrap();
            start != dir
        });
        n - self.0.len()
    }

    pub fn remove_file(&mut self, path: &str) {
        let entry = self.0.remove(path);
        assert_eq!(entry, Some(Entry::File), "{path}");
    }

    pub fn remove_empty_dir(&mut self, path: &str) {
        let entry = self.0.remove(path);
        assert_eq!(entry, Some(Entry::EmptyDir), "{path}");
    }

    pub fn assert_empty(&self) {
        assert_eq!(self.0, Default::default());
    }
}

pub fn list_fs(fs: &dyn DynFilesystem) -> Entries {
    fn list_dir(fs: &dyn DynFilesystem, dir: &Path, files: &mut BTreeMap<String, Entry>) -> usize {
        fs.read_dir_and_then(dir, &mut |iter| {
            let mut child_count = 0;
            for entry in iter {
                let entry = entry.unwrap();
                if entry.file_name().as_str() == "." || entry.file_name().as_str() == ".." {
                    continue;
                }
                child_count += 1;
                match entry.file_type() {
                    FileType::File => {
                        files.insert(entry.path().as_str().to_owned(), Entry::File);
                    }
                    FileType::Dir => {
                        let n = list_dir(fs, entry.path(), files);
                        if n == 0 {
                            files.insert(entry.path().as_str().to_owned(), Entry::EmptyDir);
                        }
                    }
                }
            }
            Ok(child_count)
        })
        .unwrap()
    }

    let mut entries = BTreeMap::new();
    list_dir(fs, path!(""), &mut entries);
    Entries(entries)
}
