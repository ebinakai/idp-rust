use argon2::{
    Argon2, PasswordVerifier,
    password_hash::{Error, PasswordHash, PasswordHasher, SaltString},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;

    let is_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    Ok(is_valid)
}

pub fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash_result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "my_super_secret_password";

        let hashed = hash_password(password).expect("ハッシュ化に失敗しました");
        assert!(hashed.starts_with("$argon2"));

        let is_valid = verify_password(password, &hashed).expect("検証に失敗しました");
        assert!(is_valid);

        let is_invalid = verify_password("wrong_password", &hashed).expect("検証に失敗しました");
        assert!(!is_invalid);
    }

    #[test]
    fn test_pkce_challenge_generation() {
        let verifier = "my_verifier";
        let challenge = generate_pkce_challenge(verifier);
        assert_eq!(challenge, "0Aw3qcaENBz7RM378ZdZZ0UXRvcqpGJSz6JnymyBeVI");
    }
}
