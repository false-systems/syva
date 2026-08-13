//! Sykli CI contract for Syva.

use sykli::Pipeline;

fn main() {
    let mut pipeline = Pipeline::new();
    let _ = pipeline.task("ci").run("make sykli-ci").inputs(&[
        "**/*.rs",
        "**/*.proto",
        "**/*.toml",
        "**/*.yaml",
        "**/*.yml",
        "Cargo.lock",
        "Makefile",
    ]);
    pipeline.emit();
}
