#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 display boot, AArch64: a picture drawn from ring 3, and looked at from
# outside the machine.
#
# **Every other boot check here believes the guest, and is right to.** A driver
# reports it read a sector and nothing else in the machine could have produced
# that value; a driver reports an interrupt arrived and nothing else could have
# woken it. The report stands in for the device because the device is the only
# thing that could have caused it.
#
# A display breaks that. Its output is not a value the guest can report — it is
# on the glass, and a driver that created the resource, attached the backing,
# set the scanout and drew nothing reports *exactly* what a working one does.
# So this script does not ask the guest whether it worked. It waits for the
# picture to be drawn, asks QEMU for the framebuffer with QMP `screendump`, and
# reads the pixels itself.
#
# The pattern is chosen so that being wrong looks wrong: red rises with the
# column and green with the row, so a wrong stride, transposed axes, a wrong
# origin and a wrong byte order each produce a *different* wrong picture. A
# flat colour would come back identical under all four, which is why the guest
# does not draw one.
# Normative: docs/drivers/03-graphics-display-media-sensors-ai.md
# ("Display And Graphics")

set -u

MARKER='claim gpu.ok'
ARMED_MARKER='claim gpu.armed'
# The claims the guest can make, separable and asserted apart.
CLASS_MARKER='claim gpu.class-served'
DREW_MARKER='claim gpu.drew-every-pixel'
REFUSED_MARKER='claim gpu.refused-not-clipped'
OUTSIDE_MARKER='claim gpu.checked-from-outside'
KERNEL="${1:?usage: gpu_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-gpu.log"
# Short and outside the sandbox tree: a UNIX socket path is bounded at 108
# bytes and a Bazel sandbox path spends most of that on its own. The screendump
# lands beside it for the same reason — QEMU writes it, not this script.
QMP_DIR="$(mktemp -d /tmp/tsgd.XXXXXX)"
QMP_SOCK="$QMP_DIR/qmp.sock"
SHOT="$QMP_DIR/screen.ppm"
: > "$SERIAL_LOG"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    exit 1
}

qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -device virtio-gpu-pci \
    -qmp "unix:$QMP_SOCK,server=on,wait=off" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native &
QEMU_PID=$!

# Wait until the picture is on the glass. Dumping before it is drawn would
# photograph a blank screen and prove the opposite of what this checks.
waited=0
until grep -qF "$ARMED_MARKER" "$SERIAL_LOG" 2>/dev/null; do
    kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU exited before arming"
    sleep 0.2
    waited=$((waited + 1))
    [ "$waited" -lt 900 ] || fail "the kernel never armed the display check"
done

[ -S "$QMP_SOCK" ] || fail "QEMU exposed no QMP socket"

printf '%s\n%s\n' \
    '{"execute":"qmp_capabilities"}' \
    "{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"$SHOT\"}}" |
    timeout 30s socat - "UNIX-CONNECT:$QMP_SOCK" > "$TMP/qmp.log" 2>&1 ||
    fail "could not drive QMP (is socat installed?)"

grep -q '"error"' "$TMP/qmp.log" &&
    fail "QMP refused the screendump: $(cat "$TMP/qmp.log")"

[ -s "$SHOT" ] || fail "QMP wrote no framebuffer"

# **The load-bearing half.** Everything above could be reported by a driver
# that drew nothing; this reads the pixels QEMU is holding.
#
# Five points, chosen so that no single mistake leaves all five right: the four
# corners fix the origin and both axes, and the centre catches a picture that
# is right at its edges and wrong in the middle. A tolerance is allowed because
# the surface QEMU hands back may have been converted from the guest's format,
# which is lossless for these values but not required to be.
python3 - "$SHOT" <<'CHECK' || fail "the picture on the glass is not the one the guest drew"
import sys

WIDTH, HEIGHT, TOLERANCE = 64, 64, 4


def expected(x, y):
    """What the client drew at (x, y): red with the column, green with the row."""
    return (x * 4, y * 4, 0x40)


with open(sys.argv[1], "rb") as handle:
    data = handle.read()

# A P6 header: magic, width, height, maxval, then one whitespace byte.
fields, at = [], 2
while len(fields) < 3:
    while at < len(data) and data[at : at + 1].isspace():
        at += 1
    if data[at : at + 1] == b"#":
        while at < len(data) and data[at] != 0x0A:
            at += 1
        continue
    start = at
    while at < len(data) and not data[at : at + 1].isspace():
        at += 1
    fields.append(int(data[start:at]))
at += 1

if data[:2] != b"P6":
    sys.exit("the screendump is not a binary PPM")
width, height, maxval = fields
if maxval != 255:
    sys.exit(f"unexpected sample depth {maxval}")
if (width, height) != (WIDTH, HEIGHT):
    sys.exit(f"the screen is {width}x{height}, not the {WIDTH}x{HEIGHT} scanout the guest set")

pixels = data[at:]
if len(pixels) < width * height * 3:
    sys.exit("the screendump is shorter than the screen it claims")


def at_pixel(x, y):
    off = (y * width + x) * 3
    return tuple(pixels[off : off + 3])


bad = []
for x, y in ((0, 0), (WIDTH - 1, 0), (0, HEIGHT - 1), (WIDTH - 1, HEIGHT - 1), (WIDTH // 2, HEIGHT // 2)):
    got, want = at_pixel(x, y), expected(x, y)
    if any(abs(g - w) > TOLERANCE for g, w in zip(got, want)):
        bad.append(f"({x},{y}): saw {got}, drew {want}")

# A picture that is right at five points and blank everywhere else is not a
# picture. Every pixel is a known colour, so every pixel can be checked.
wrong = sum(
    1
    for y in range(height)
    for x in range(width)
    if any(abs(g - w) > TOLERANCE for g, w in zip(at_pixel(x, y), expected(x, y)))
)

if bad or wrong:
    for line in bad:
        print(f"  {line}", file=sys.stderr)
    print(f"  {wrong} of {width * height} pixels differ from what the client drew", file=sys.stderr)
    sys.exit(1)

print(f"the framebuffer QEMU holds is the {width}x{height} pattern the client drew, every pixel")
CHECK

wait "$QEMU_PID"
status=$?
rm -rf "$QMP_DIR"

case "$status" in
    33) ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$CLASS_MARKER" "$DREW_MARKER" "$REFUSED_MARKER" "$OUTSIDE_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the display claim did not hold: '$marker'"
done

echo "PASS: clean exit 33, a ring-3 driver served the display class, and the picture a ring-3 client drew through that contract is the one QEMU had on the glass"
