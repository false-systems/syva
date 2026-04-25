use crate::policy::load_policies_from_dir;
use anyhow::Result;
use std::path::Path;

pub fn run(policy_dir: &Path) -> Result<()> {
    let policies = load_policies_from_dir(policy_dir)?;
    println!(
        "Validated {} policies in {}",
        policies.len(),
        policy_dir.display()
    );
    for name in policies.keys() {
        println!("  OK {name}");
    }
    Ok(())
}
