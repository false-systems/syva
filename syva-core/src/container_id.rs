/// Validate that a container ID is safe to accept from local adapters.
pub(crate) fn is_valid_container_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::is_valid_container_id;

    #[test]
    fn accepts_containerd_like_ids() {
        assert!(is_valid_container_id("abc123"));
        assert!(is_valid_container_id("abc-def_123"));
        assert!(is_valid_container_id(&"a".repeat(128)));
    }

    #[test]
    fn rejects_path_or_shell_shaped_ids() {
        assert!(!is_valid_container_id(""));
        assert!(!is_valid_container_id("../../../etc/passwd"));
        assert!(!is_valid_container_id("abc/def"));
        assert!(!is_valid_container_id("abc def"));
        assert!(!is_valid_container_id(&"a".repeat(129)));
    }
}
