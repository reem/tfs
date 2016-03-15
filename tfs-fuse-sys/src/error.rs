use std::borrow::Cow;
use std::error::Error;
use std::{fmt, io};

#[derive(Debug, PartialEq)]
pub struct OperationNotSupported(Cow<'static, str>);

impl OperationNotSupported {
    pub fn new<S: Into<Cow<'static, str>>>(s: S) -> Self {
        OperationNotSupported(s.into())
    }

    pub fn io<S: Into<Cow<'static, str>>>(s: S) -> io::Error {
        io::Error::new(io::ErrorKind::Other, Self::new(s))
    }

    pub fn operation(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OperationNotSupported {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Operation Not Supported: {}", self.operation())
    }
}

impl Error for OperationNotSupported {
    fn description(&self) -> &str {
        "Operation Not Supported"
    }
}

