# swaylock-fprintd

Fork of [swaywm/swaylock](https://github.com/swaywm/swaylock) that adds a
`--fingerprint` flag so the lock screen accepts a fingerprint **and** a typed
password at the same time, with neither blocking the other.

## Why this fork

Stock swaylock has a single, synchronous PAM conversation that doesn't start
until you press Enter, and a `pam_fprintd` line in that stack couples the two:
a pending or failed finger scan blocks password entry, so one wrong finger can
wedge the whole lock screen.

This fork runs **two independent PAM children concurrently** (see `comm.c` and
`pam.c`):

- a **fingerprint child** that scans on a loop, retrying ~0.4s after each miss,
  with no password prompt and no limit on retries;
- the unmodified **password child**, which you can type into at any time.

Whichever authenticates first unlocks the session; the parent then SIGKILLs the
other child so `fprintd` releases the reader. A missed scan never disrupts
typing, and typing never cancels scanning.

When `--fingerprint` is set the indicator ring also stays visible while idle, so
the locker doesn't look like an unresponsive black screen.

## Required PAM setup

The concurrency relies on **two separate PAM services** — the fingerprint child
must never fall through to a password prompt, and the password child must never
touch `pam_fprintd`:

`/etc/pam.d/swaylock` (password only):

```
auth      required  pam_unix.so try_first_pass nullok
account   include   system-auth
session   include   system-auth
```

`/etc/pam.d/swaylock-fp` (fingerprint only):

```
auth      required  pam_fprintd.so max-tries=10
account   include   system-auth
session   include   system-auth
```

> **Do not install the binary setuid.** It uses the PAM backend, and setuid +
> PAM makes it abort on launch. PAM reads `/etc/shadow` itself, so both the
> fingerprint and password paths work from a normal `0755` binary. If a package
> ever re-adds the setuid bit, clear it with `chmod a-s`.

## Usage

```sh
swaylock-fprintd --fingerprint -c 000000
```

Recommended swayidle setup (note the paired `resume` so the display wakes from
DPMS-off — without it the screen stays black when you return):

```sh
exec swayidle -w \
    timeout 300 'swaylock-fprintd --fingerprint -c 000000' \
    timeout 600 'swaymsg "output * dpms off"' resume 'swaymsg "output * dpms on"' \
    before-sleep 'swaylock-fprintd --fingerprint -c 000000' \
    lock 'swaylock-fprintd --fingerprint -c 000000'
```

## Building

```sh
meson setup build -Dpam=enabled -Dgdk-pixbuf=disabled
ninja -C build
install -m0755 build/swaylock ~/.local/bin/swaylock-fprintd   # NOT setuid
```

Use `meson setup --reconfigure build` if `build/` already exists.

Requires: `wayland-devel`, `wayland-protocols`, `libxkbcommon-devel`,
`cairo-devel`, `pam-libs`.

---

# swaylock

swaylock is a screen locking utility for Wayland compositors. It is compatible
with any Wayland compositor which implements the ext-session-lock-v1 Wayland
protocol.

See the man page, [swaylock(1)](swaylock.1.scd), for instructions on using swaylock.

## Release Signatures

Releases are signed with [E88F5E48](https://keys.openpgp.org/search?q=34FF9526CFEF0E97A340E2E40FDE7BE0E88F5E48)
and published [on GitHub](https://github.com/swaywm/swaylock/releases). swaylock
releases are managed independently of sway releases.

## Installation

### From Packages

Swaylock is available in many distributions. Try installing the "swaylock"
package for yours.

### Compiling from Source

Install dependencies:

* meson \*
* wayland
* wayland-protocols \*
* libxkbcommon
* cairo
* gdk-pixbuf2 \*\*
* pam (optional)
* [scdoc](https://git.sr.ht/~sircmpwn/scdoc) (optional: man pages) \*
* git \*

_\* Compile-time dep_  
_\*\* Optional: required for background images other than PNG_

Run these commands:

    meson build
    ninja -C build
    sudo ninja -C build install

##### Without PAM

On systems without PAM, swaylock uses `shadow.h`.

Systems which rely on a tcb-like setup (either via musl's native support or via
glibc+[tcb]), require no further action.

[tcb]: https://www.openwall.com/tcb/

For most other systems, where passwords for all users are stored in `/etc/shadow`,
swaylock needs to be installed suid:

    sudo chmod a+s /usr/local/bin/swaylock

Optionally, on systems where the file `/etc/shadow` is owned by the `shadow`
group, the binary can be made sgid instead:

    sudo chgrp shadow /usr/local/bin/swaylock
    sudo chmod g+s /usr/local/bin/swaylock

Swaylock will drop root permissions shortly after startup.
