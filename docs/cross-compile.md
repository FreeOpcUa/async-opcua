# Cross-compiling OPC UA for Rust

The Raspberry Pi will be used as the target device for this document. If you have another target, e.g. some `bitbake` concoction, then you will have to adapt the instructions accordingly.

Cross compilation is described in two ways - one that uses the `cross` tool and one that is manual. Depending on your needs you may decide on one or the other. 

## Build with Cross

The `cross` tool attempts to make it as simple as possible to cross-compile software by automatically fetching the appropriate cross compile toolchain and environment.

Install [docker](https://www.docker.com/) if you have not already.

```
$ sudo apt install docker.io
```

Install [cross](https://github.com/rust-embedded/cross) for Rust.

```
$ cargo install cross
```

Install the tool according its own instructions. Ensure your docker permissions are set. Now you can use `cross` in place of `cargo`. e.g.

```
$ cross build --all --target armv7-unknown-linux-gnueabihf
```

The additional argument `--target armv7-unknown-linux-gnueabihf` tells `cross` to set up a build environment before invoking `cargo`.

### SELinux conflict

The `cross` tool may have an [issue](https://github.com/rust-embedded/cross/issues/112) running `cargo` on Fedora / Red Hat dists due to a SELinux policy. Read the bug for a workaround.
