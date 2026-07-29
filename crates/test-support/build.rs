#[path = "../../build-support/git_stamp.rs"]
mod git_stamp;

fn main() {
    git_stamp::emit(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
}
