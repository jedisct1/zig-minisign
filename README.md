# zig-minisign

A Zig implementation of [Minisign](https://jedisct1.github.io/minisign/).

`minizign` was primarily designed to verify signatures, although signing is likely to be implemented next.

## Compilation

Requires the current `master` version of [Zig](https://ziglang.org).

Compile with:

```sh
zig build -Drelease-small
```

for a size-optimized version, or

```sh
zig build -Drelease-fast
```

for a speed-optimized version.

## Usage

```text
Usage:
    -h, --help                  Display this help and exit
    -p, --publickey-path <PATH> Public key path to a file
    -P, --publickey <STRING>    Public key, as a BASE64-encoded string
    -l, --legacy                Accept legacy signatures
    -m, --input <PATH>          Input file
    -q, --quiet                 Quiet mode
    -V, --verify                Verify
    -C, --convert               Convert the given public key to SSH format
```

## Example

Verify `public-resolvers.md` using `public-resolvers.md.minisig` and the public key file `minisig.pub`:

```sh
minizign -p minisign.pub -Vm public-resolvers.md
```

Verify `public-resolvers.md` by directly providing the public key on the command-line:

```sh
minizign -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3 -Vm public-resolvers.md
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
