#[cfg(target_os = "windows")]
pub mod signing_certificate {
    use sha2::{Digest, Sha256};
    use std::env;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows::Win32::Security::Cryptography::*;

    #[derive(Debug)]
    pub struct SigningCertificateInfo {
        pub subject: String,
        pub thumbprint_sha256: String,
    }

    pub fn get_signing_certificate() -> Result<SigningCertificateInfo, String> {
        unsafe {
            let exe_path =
                env::current_exe().map_err(|e| format!("Failed to get executable path: {}", e))?;

            let exe_wide: Vec<u16> = exe_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut encoding = CERT_QUERY_ENCODING_TYPE(0);
            let mut content_type = CERT_QUERY_CONTENT_TYPE(0);
            let mut format_type = CERT_QUERY_FORMAT_TYPE(0);
            let mut cert_store = HCERTSTORE::default();
            let mut crypt_msg: *mut c_void = null_mut();
            let mut context: *mut c_void = null_mut();

            let result = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                exe_wide.as_ptr() as *const c_void,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                Some(&mut encoding as *mut _),
                Some(&mut content_type as *mut _),
                Some(&mut format_type as *mut _),
                Some(&mut cert_store as *mut _),
                Some(&mut crypt_msg as *mut _),
                Some(&mut context as *mut _),
            );

            if result.is_err() {
                return Err("No embedded Authenticode signature found".into());
            }

            let cert_context = CertEnumCertificatesInStore(cert_store, None);

            if cert_context.is_null() {
                let _ = CertCloseStore(Some(cert_store), 0);
                return Err("No certificate found in certificate store".into());
            }

            let cert_info = (*cert_context).pCertInfo;

            // Extract subject
            let subject_len =
                CertNameToStrW(encoding, &(*cert_info).Subject, CERT_X500_NAME_STR, None);

            let mut subject_buf = vec![0u16; subject_len as usize];

            CertNameToStrW(
                encoding,
                &(*cert_info).Subject,
                CERT_X500_NAME_STR,
                Some(&mut subject_buf),
            );

            let subject = String::from_utf16_lossy(&subject_buf)
                .trim_matches(char::from(0))
                .to_string();

            // Compute SHA256 thumbprint over DER-encoded certificate
            let cert_bytes = std::slice::from_raw_parts(
                (*cert_context).pbCertEncoded,
                (*cert_context).cbCertEncoded as usize,
            );

            let mut hasher = Sha256::new();
            hasher.update(cert_bytes);
            let thumbprint = hex::encode(hasher.finalize());

            let _ = CertFreeCertificateContext(Some(cert_context as *const _));
            let _ = CertCloseStore(Some(cert_store), 0);

            Ok(SigningCertificateInfo {
                subject,
                thumbprint_sha256: thumbprint,
            })
        }
    }
}

#[cfg(target_os = "macos")]
pub mod signing_certificate {
    use hex;
    use security_framework::certificate::SecCertificate;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug)]
    pub struct SigningCertificateInfo {
        pub subject: String,
        pub thumbprint_sha256: String,
    }

    pub fn get_signing_certificate() -> Result<SigningCertificateInfo, String> {
        let path =
            std::env::current_exe().map_err(|e| format!("Failed to get executable path: {}", e))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to compute timestamp: {}", e))?
            .as_nanos();
        let temp_dir: PathBuf = std::env::temp_dir().join(format!(
            "centralauth-signing-cert-{}-{}",
            std::process::id(),
            timestamp
        ));

        fs::create_dir_all(&temp_dir)
            .map_err(|e| format!("Failed to create temp directory: {}", e))?;

        let output = Command::new("codesign")
            .arg("-d")
            .arg("--extract-certificates")
            .arg(&path)
            .current_dir(&temp_dir)
            .output()
            .map_err(|e| format!("Failed to run codesign: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(format!(
                "Failed to extract signing certificate from executable: {}",
                stderr.trim()
            ));
        }

        let leaf_cert_path = temp_dir.join("codesign0");
        let der = fs::read(&leaf_cert_path)
            .map_err(|e| format!("Failed to read extracted leaf certificate: {}", e))?;
        let _ = fs::remove_dir_all(&temp_dir);

        let leaf_cert = SecCertificate::from_der(&der)
            .map_err(|e| format!("Failed to parse leaf certificate DER: {:?}", e))?;

        let mut hasher = Sha256::new();
        hasher.update(&der);
        let thumbprint = hex::encode(hasher.finalize());

        let subject = leaf_cert.subject_summary();

        Ok(SigningCertificateInfo {
            subject,
            thumbprint_sha256: thumbprint,
        })
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[allow(dead_code)]
pub mod signing_certificate {
    #[derive(Debug)]
    pub struct SigningCertificateInfo {
        pub subject: String,
        pub thumbprint_sha256: String,
    }

    pub fn get_signing_certificate() -> Result<SigningCertificateInfo, String> {
        Err("Signing certificate retrieval is only supported on Windows and MacOS".into())
    }
}
