fn main() {
    // trigger recompilation when a sql migration is added or changed.
    println!("cargo:rerun-if-changed=grafton-server/migrations");
}
