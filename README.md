# zig-minisign

A Zig implementation of [Minisign](https://jedisct1.github.io/minisign/).

`minizign` supports signature verification, signing, and key generation.

## Compilation

Requires the current `master` version of [Zig](https://ziglang.org).

Compile with:

```sh
zig build -Doptimize=ReleaseSmall
```

for a size-optimized version, or

```sh
zig build -Doptimize=ReleaseFast
```

for a speed-optimized version.

## Usage

```text
Usage:
    -h, --help                       Display this help and exit
    -p, --publickey-path <PATH>      Public key path to a file
    -P, --publickey <STRING>         Public key, as a BASE64-encoded string
    -s, --secretkey-path <PATH>      Secret key path to a file
    -l, --legacy                     Accept legacy signatures
    -m, --input <PATH>...            Input file(s)
    -o, --output <PATH>              Output file (signature)
    -q, --quiet                      Quiet mode
    -V, --verify                     Verify
    -S, --sign                       Sign
    -G, --generate                   Generate a new key pair
    -R, --recreate                   Recreate public key from secret key
    -K, --change-password            Change secret key password
    -C, --convert                    Convert the given public key to SSH format
    -t, --trusted-comment <STRING>   Trusted comment
    -c, --untrusted-comment <STRING> Untrusted comment
```

## Examples

### Key Generation

Generate a new key pair:

```sh
minizign -G -s minisign.key -p minisign.pub
```

This will prompt for a password to encrypt the secret key. Leave empty for an unencrypted key.

### Signing

Sign a file:

```sh
minizign -S -s minisign.key -m file.txt
```

This creates `file.txt.minisig`. You can specify a custom output path with `-o`.

Sign multiple files at once:

```sh
minizign -S -s minisign.key -m file1.txt -m file2.txt -m file3.txt
```

### Recreate Public Key

If you lose your public key file, you can recreate it from the secret key:

```sh
minizign -R -s minisign.key -p minisign.pub
```

### Change Password

Change the password on an existing secret key:

```sh
minizign -K -s minisign.key
```

This prompts for the current password (if encrypted), then asks for a new password with confirmation. Leave the new password empty to remove encryption.

### Verification

Verify `public-resolvers.md` using `public-resolvers.md.minisig` and the public key file `minisign.pub`:

```sh
minizign -V -p minisign.pub -m public-resolvers.md
```

Verify `public-resolvers.md` by directly providing the public key on the command-line:

```sh
minizign -V -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3 -m public-resolvers.md
```

## SSH-encoded public keys

`minizign` can encode public keys in SSH format, so that they can be uploaded to GitHub:

```sh
minizign -p minisign.pub -C
```

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHmlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3 minisign key E7620F1842B4E81F
```

GitHub makes public SSH keys available at `https://github.com/<username>.keys`.

SSH-encoded keys can be loaded by `minizign` the same way as native keys, with `-p <key file>`. They will be automatically recognized as such.

## Features

`minizign` supports prehashing (which can be forced if you know this is how the signature was created), has zero dependencies and can be cross-compiled to anything that Zig can cross-compile to, including WebAssembly.
