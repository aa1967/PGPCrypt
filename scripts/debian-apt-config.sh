# Source this file only from the rootless cloud bootstrap scripts.
configure_cloud_apt() {
    test "$(dpkg --print-architecture)" = amd64
    mkdir -p "$apt_root/lists/partial" "$apt_root/archives/partial" "$apt_root/parts"
    cat > "$apt_root/apt.conf" <<EOF
Dir::Etc::Parts "$apt_root/parts";
Dir::Etc::main "$apt_root/empty.conf";
Dir::Etc::sourcelist "$apt_root/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "$apt_root/lists";
Dir::Cache::archives "$apt_root/archives";
Dir::Log "$apt_root";
APT::Sandbox::User "$(id -un)";
Debug::NoLocking "true";
APT::Install-Recommends "false";
EOF
    cat > "$apt_root/sources.list" <<'EOF'
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie-backports main
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://security.debian.org/debian-security trixie-security main
EOF
    export APT_CONFIG="$apt_root/apt.conf"
}
