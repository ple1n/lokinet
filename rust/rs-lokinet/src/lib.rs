use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;

unsafe extern "C" {
    fn lokinet_context_new() -> *mut RawLokinet;
    fn lokinet_context_set_config(
        config: *const c_char,
        data_dir: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_size: usize,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_context_start(context: *mut RawLokinet) -> c_int;
    fn lokinet_status(context: *mut RawLokinet) -> c_int;
    fn lokinet_context_free(context: *mut RawLokinet);
}

#[repr(C)]
struct RawLokinet {
    _private: [u8; 0],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    config_text: String,
    data_dir: PathBuf,
}

impl Config {
    pub fn new(config_text: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_text: config_text.into(),
            data_dir: data_dir.into(),
        }
    }

    pub fn validate(self) -> Result<ValidatedConfig, Error> {
        if self.config_text.contains('\0') {
            return Err(Error::InvalidString);
        }
        if !self.data_dir.is_absolute() {
            return Err(Error::DataDirectoryMustBeAbsolute(self.data_dir));
        }
        Ok(ValidatedConfig {
            config_text: self.config_text,
            data_dir: self.data_dir,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedConfig {
    config_text: String,
    data_dir: PathBuf,
}

impl ValidatedConfig {
    pub fn config_text(&self) -> &str {
        &self.config_text
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[derive(Debug)]
pub enum Error {
    DataDirectoryMustBeAbsolute(PathBuf),
    InvalidString,
    Native(String),
    NullHandle,
    NonUtf8Path(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataDirectoryMustBeAbsolute(path) => {
                write!(
                    f,
                    "Lokinet data directory must be absolute: {}",
                    path.display()
                )
            }
            Self::InvalidString => write!(f, "Lokinet config contains an interior NUL"),
            Self::Native(message) => write!(f, "Lokinet initialization failed: {message}"),
            Self::NullHandle => write!(f, "Lokinet returned a null handle"),
            Self::NonUtf8Path(path) => {
                write!(
                    f,
                    "Lokinet data directory is not valid UTF-8: {}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for Error {}

pub struct Runtime {
    raw: NonNull<RawLokinet>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Runtime {
    pub fn start(config: Config) -> Result<Self, Error> {
        let config = config.validate()?;
        let config_text = CString::new(config.config_text).map_err(|_| Error::InvalidString)?;
        let data_dir = config
            .data_dir
            .to_str()
            .ok_or_else(|| Error::NonUtf8Path(config.data_dir.clone()))?;
        let data_dir = CString::new(data_dir).map_err(|_| Error::InvalidString)?;

        let raw = NonNull::new(unsafe { lokinet_context_new() }).ok_or(Error::NullHandle)?;
        let mut runtime = Self {
            raw,
            _not_send_or_sync: PhantomData,
        };
        let mut error_buffer = [0 as c_char; 1024];
        let result = unsafe {
            lokinet_context_set_config(
                config_text.as_ptr(),
                data_dir.as_ptr(),
                error_buffer.as_mut_ptr(),
                error_buffer.len(),
                runtime.raw.as_ptr(),
            )
        };
        if result != 0 {
            let message = unsafe { CStr::from_ptr(error_buffer.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(Error::Native(message));
        }

        if unsafe { lokinet_context_start(runtime.raw.as_ptr()) } != 0 {
            return Err(Error::Native(
                "failed to start the Lokinet context".to_owned(),
            ));
        }
        Ok(runtime)
    }

    pub fn is_connected(&self) -> bool {
        unsafe { lokinet_status(self.raw.as_ptr()) == 0 }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe { lokinet_context_free(self.raw.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_state_directory() {
        let err = Config::new("", "relative-state").validate().unwrap_err();
        assert!(matches!(err, Error::DataDirectoryMustBeAbsolute(_)));
    }

    #[test]
    fn accepts_explicit_absolute_state_directory() {
        let config = Config::new("", "/state/lokinet").validate().unwrap();
        assert_eq!(config.data_dir(), Path::new("/state/lokinet"));
    }
}
