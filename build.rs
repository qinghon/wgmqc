use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/wgredir.bpf.c";

fn main() {
	let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
	out.push("wgredir.skel.rs");

	let c_args = vec![
		"-Wall".to_string(),
		"-Wno-compare-distinct-pointer-types".to_string(),
		"-mcpu=v3".to_string(),
		#[cfg(debug_assertions)]
		"-Werror".to_string(),
	];

	SkeletonBuilder::new().source(SRC).clang_args(c_args).debug(true).build_and_generate(&out).unwrap();
	println!("cargo:rerun-if-changed={SRC}");
}
