use std::fs;
use std::io;
use std::path::PathBuf;

pub trait TelemetrySource: Send + Sync {
    fn read_to_string(&self, absolute_path: &str) -> io::Result<String>;
    fn read_dir_names(&self, absolute_path: &str) -> io::Result<Vec<String>>;
    fn read_link(&self, absolute_path: &str) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("symbolic link reads are unavailable for {absolute_path}"),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct FsSource {
    root: PathBuf,
}

impl FsSource {
    #[must_use]
    pub fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    #[must_use]
    pub fn rooted_at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn resolve(&self, absolute_path: &str) -> PathBuf {
        self.root.join(absolute_path.trim_start_matches('/'))
    }
}

impl TelemetrySource for FsSource {
    fn read_to_string(&self, absolute_path: &str) -> io::Result<String> {
        fs::read_to_string(self.resolve(absolute_path))
    }

    fn read_dir_names(&self, absolute_path: &str) -> io::Result<Vec<String>> {
        let mut names = fs::read_dir(self.resolve(absolute_path))?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    fn read_link(&self, absolute_path: &str) -> io::Result<PathBuf> {
        fs::read_link(self.resolve(absolute_path))
    }
}

pub(crate) fn read_optional(
    source: &dyn TelemetrySource,
    path: &str,
) -> io::Result<Option<String>> {
    match source.read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
