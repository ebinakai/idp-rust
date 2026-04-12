use argon2::{
    Argon2, PasswordVerifier, password_hash::{
        Error,
        PasswordHash,
        PasswordHasher,
        SaltString
    }
};
use rand_core::OsRng;

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;

    let is_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    Ok(is_valid)
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
}