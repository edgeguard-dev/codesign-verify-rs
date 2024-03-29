#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
pub use macos::errSecCSBadResource;
#[cfg(target_os = "macos")]
use macos::{Context, Verifier};

use std::collections::HashMap;
#[cfg(windows)]
use windows::{Context, Verifier};

///
/// Used to verify the validity of a code signature
///
pub struct CodeSignVerifier(Verifier);

///
/// Used to extract additional information from the signing leaf certificate
///
pub struct SignatureContext(Context);

///
/// Represents an Issuer or Subject name with the following fields:
///
/// # Fields
///
/// `common_name`: OID 2.5.4.3
///
/// `organization`: OID 2.5.4.10
///
/// `organization_unit`: OID 2.5.4.11
///
/// `country`: OID 2.5.4.6
///
#[derive(Debug, PartialEq)]
pub struct Name {
    pub common_name: Option<String>,       // 2.5.4.3
    pub organization: Option<String>,      // 2.5.4.10
    pub organization_unit: Option<String>, // 2.5.4.11
    pub country: Option<String>,           // 2.5.4.6
}

#[derive(Debug)]
pub enum Error {
    Unsigned,         // The binary file didn't have any singature
    OsError(i32),     // Warps an inner provider error code
    InvalidPath,      // The provided path was malformed
    LeafCertNotFound, // Unable to fetch certificate information
    #[cfg(target_os = "macos")]
    CFError(core_foundation::error::CFError),
    #[cfg(windows)]
    IoError(std::io::Error),
}

impl CodeSignVerifier {
    /// Create a verifier for a binary at a given path.
    /// On macOS it can be either a binary or an application package.
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        Verifier::for_file(path).map(|v| CodeSignVerifier(v))
    }

    /// Create a verifier for a running application by PID.
    /// On Windows it will get the full path to the running application first.
    /// This can be used for e.g. verifying the app on the other end of a pipe.
    pub fn for_pid(pid: i32) -> Result<Self, Error> {
        Verifier::for_pid(pid).map(|v| CodeSignVerifier(v))
    }

    /// Perform the verification itself.
    /// On macOS the verification uses the Security framework with "anchor trusted" as the requirement.
    /// On Windows the verification uses WinTrust and the `WINTRUST_ACTION_GENERIC_VERIFY_V2` action.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use codesign_verify::CodeSignVerifier;
    ///
    /// CodeSignVerifier::for_file("C:/Windows/explorer.exe").unwrap().verify("").unwrap();
    /// ```
    pub fn verify(self, requirement: &str) -> Result<SignatureContext, Error> {
        self.0.verify(requirement).map(|c| SignatureContext(c))
    }
}

impl SignatureContext {
    /// Retrieve the subject name on the leaf certificate
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use codesign_verify::CodeSignVerifier;
    ///
    /// let ctx = CodeSignVerifier::for_file("C:/Windows/explorer.exe").unwrap().verify("").unwrap();
    /// assert_eq!(
    ///    ctx.subject_name().organization.as_deref(),
    ///    Some("Microsoft Corporation")
    /// );
    ///
    /// ```
    pub fn subject_name(&self) -> Name {
        self.0.subject_name()
    }

    /// Retrieve the issuer name on the leaf certificate
    pub fn issuer_name(&self) -> Name {
        self.0.issuer_name()
    }

    /// Compute the sha256 thumbprint of the leaf certificate
    pub fn sha256_thumbprint(&self) -> String {
        self.0.sha256_thumbprint()
    }

    /// Retrieve the leaf certificate serial number
    pub fn serial(&self) -> Option<String> {
        self.0.serial()
    }

    /// Additional properties.
    pub fn additional_properties(&self) -> Option<HashMap<String, String>> {
        self.0.additional_properties()
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;
    use std::collections::HashMap;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_signed() {
        let verifier = super::CodeSignVerifier::for_file("/sbin/ping").unwrap(); // Should always be present on macOS
        let ctx = verifier.verify("anchor apple generic").unwrap(); // Should always be signed

        // If those values begin to fail, Apple probably changed their certficate
        assert_eq!(
            ctx.subject_name().organization.as_deref(),
            Some("Apple Inc.")
        );

        assert_eq!(
            ctx.issuer_name().organization_unit.as_deref(),
            Some("Apple Certification Authority")
        );

        assert_eq!(
            ctx.additional_properties(),
            Some(HashMap::from([
                (
                    "cd_hash".to_string(),
                    "AEE97B850A12F9CAC3EC399094071CAD63325818".to_string()
                ),
                ("platform_id".to_string(), "15".to_string())
            ]))
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_signed() {
        let path = format!("{}/explorer.exe", std::env::var("windir").unwrap()); // Should always be present on Windows
        let verifier = super::CodeSignVerifier::for_file(path).unwrap();
        let ctx = verifier.verify("").unwrap(); // Should always be signed

        // If those values begin to fail, Microsoft probably changed their certficate
        assert_eq!(
            ctx.subject_name().organization.as_deref(),
            Some("Microsoft Corporation")
        );

        assert_eq!(
            ctx.issuer_name().common_name.as_deref(),
            Some("Microsoft Windows Production PCA 2011")
        );

        assert_eq!(
            ctx.serial().as_deref(),
            Some("3300000266bd1580efa75cd6d3000000000266")
        );
    }

    #[test]
    fn test_unsigned() {
        let path = std::env::args().next().unwrap(); // own path, always unsigned and present

        let res = super::CodeSignVerifier::for_file(path)
            .unwrap()
            .verify("anchor apple");
        assert!(
            matches!(res, Err(Error::Unsigned)),
            "error = {:?}",
            res.err()
        );
    }
}
