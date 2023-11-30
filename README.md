# revsh-rs

Rust implementation of [revsh](https://github.com/emptymonkey/revsh) protocol and control handler. Allows for receiving callbacks from a revsh target.

## Features

* Working
    * SSL
    * Shell
    * SOCKS 4 proxy
    * TTY
        * Job control
        * CTRL-C
        * Auto-completion
        * Window resizing events

* Not working
    * VPN
    * SOCKS 5 proxy
    * Escape sequences
    * Netcat style non-interactive data brokering

## Use of unsafe

Unsafe is used to do terminal handling and handle window resizing events. If no need TTY use `--no-default-features` to disable TTY.

Also because of how code structured, used static mut.

## Usage

First go original revsh keys dir and convert keys to pfx with no export password:

```
openssl pkcs12 -export -out control_identity.pfx -inkey control_key.pem -in control_cert.pem
openssl pkcs12 -export -out target_identity.pfx -inkey target_key.pem -in target_cert.pem
```

Build project:

```
TARGET_KEY_FILE=/path/to/revsh/keys/target_identity.pfx cargo build --release
```

Run control:

```
$ target/release/control -h
revsh-rs control

USAGE:
    control [OPTIONS] [address]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -D <dynamic_socket_forwarding>        Dynamic socket forwarding with a local listener
    -d <keys_dir>                         Reference the keys in an alternate directory [default: ~/.revsh/keys/]

ARGS:
    <address>    The address of the control listener [default: 0.0.0.0:2200]
```

```
$ target/release/control -d ../revsh/keys/ -D 127.0.0.1:1080 0.0.0.0:2200
```
