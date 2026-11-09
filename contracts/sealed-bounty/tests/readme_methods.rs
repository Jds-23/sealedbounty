//! Docs check (#16): every `pub fn` of the contract in src/lib.rs must be documented in README.md
//! as `` `name(`` or `` `name` ``. Fails with the list of undocumented methods.

const LIB: &str = include_str!("../src/lib.rs");
const README: &str = include_str!("../README.md");

fn pub_fns(src: &str) -> Vec<&str> {
    src.lines()
        .filter_map(|l| l.trim_start().strip_prefix("pub fn "))
        .map(|rest| rest.split(['(', '<']).next().unwrap().trim())
        .collect()
}

#[test]
fn every_pub_fn_is_in_readme() {
    let fns = pub_fns(LIB);
    assert!(
        fns.len() >= 20,
        "expected the contract's methods, found {fns:?}"
    );
    let missing: Vec<&str> = fns
        .iter()
        .copied()
        .filter(|f| !README.contains(&format!("`{f}(")) && !README.contains(&format!("`{f}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "README.md is missing pub fns: {missing:?}"
    );
    println!("README documents all {} pub fns: {fns:?}", fns.len());
}
