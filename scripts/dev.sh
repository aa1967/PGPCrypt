#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_root=$(dirname -- "$repo_root")/.pgpcrypt-tools
if [ -x /usr/bin/cargo ] && [ -x /usr/bin/rustc ]; then
    # A normal Debian source build uses its package-managed compiler.
    export PATH="/usr/bin:$PATH"
elif [ -x "$tools_root/debian-rust/usr/bin/cargo" ]; then
    # Rootless extraction of the same authenticated Debian packages in cloud.
    export PATH="$tools_root/debian-rust/usr/bin:$PATH"
    export LD_LIBRARY_PATH="$tools_root/debian-rust/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    # Do not put rustup proxy binaries in Debian Cargo's external-command path.
    # Reuse registry downloads without reusing the old toolchain's bin directory.
    export CARGO_HOME="$tools_root/debian-cargo"
    mkdir -p "$CARGO_HOME"
    if [ -d "$tools_root/cargo/registry" ] && [ ! -e "$CARGO_HOME/registry" ]; then
        ln -s "$tools_root/cargo/registry" "$CARGO_HOME/registry"
    fi
else
    echo "Install the Debian build tools: sudo apt install rustc cargo" >&2
    exit 1
fi
# The cloud image has libclang but omits its resource headers. GCC's standard
# C headers provide the missing stddef.h for OpenSSL's bindgen invocation.
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:-} -I$(gcc -print-file-name=include)"
if [ -d "$tools_root/debian-sodium/usr/lib/x86_64-linux-gnu" ]; then
    export LIBRARY_PATH="$tools_root/debian-sodium/usr/lib/x86_64-linux-gnu${LIBRARY_PATH:+:$LIBRARY_PATH}"
fi
cd "$repo_root"
exec cargo "$@"
