#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Paths (can be overridden by environment variables)
MINISIGN="${MINISIGN:-minisign}"
MINIZIGN="${MINIZIGN:-./zig-out/bin/minizign}"
TEST_DIR="./tmp/compat_test"

# Check binaries exist
if ! command -v "$MINISIGN" >/dev/null 2>&1; then
    echo -e "${RED}Error: minisign not found${NC}"
    echo "Install minisign or set MINISIGN environment variable"
    exit 1
fi

if ! command -v "$MINIZIGN" >/dev/null 2>&1; then
    echo -e "${RED}Error: minizign not found${NC}"
    echo "Run 'zig build' first or set MINIZIGN environment variable"
    exit 1
fi

# Helper functions
log_test() {
    echo -e "${YELLOW}TEST $((TESTS_RUN + 1)): $1${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))
}

log_pass() {
    echo -e "${GREEN}✓ PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}✗ FAIL: $1${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

cleanup() {
    rm -rf "$TEST_DIR"
}

setup() {
    cleanup
    mkdir -p "$TEST_DIR"
    echo "Test data for minisign compatibility" > "$TEST_DIR/test.txt"
}

# Trap to cleanup on exit
trap cleanup EXIT

echo "=== Minisign <-> Minizign Compatibility Test ==="
echo "minisign: $($MINISIGN -v 2>&1 | head -n1 || echo 'unknown')"
echo "minizign: Zig implementation"
echo ""

setup

# Test 1: Generate with minisign, sign with minisign, verify with minizign
log_test "Generate(C) → Sign(C) → Verify(Zig)"
printf "\n\n" | $MINISIGN -G -p "$TEST_DIR/test1.pub" -s "$TEST_DIR/test1.key" >/dev/null 2>&1
printf "\n" | $MINISIGN -S -s "$TEST_DIR/test1.key" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test1.txt.minisig" >/dev/null 2>&1
if $MINIZIGN -V -p "$TEST_DIR/test1.pub" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test1.txt.minisig" >/dev/null 2>&1; then
    log_pass
else
    log_fail "Verification failed"
fi

# Test 2: Generate with minizign, sign with minizign, verify with minisign
log_test "Generate(Zig) → Sign(Zig) → Verify(C)"
printf "\n" | $MINIZIGN -G -s "$TEST_DIR/test2.key" -p "$TEST_DIR/test2.pub" >/dev/null 2>&1
printf "\n" | $MINIZIGN -S -s "$TEST_DIR/test2.key" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test2.txt.minisig" >/dev/null 2>&1
if $MINISIGN -V -p "$TEST_DIR/test2.pub" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test2.txt.minisig" >/dev/null 2>&1; then
    log_pass
else
    log_fail "Verification failed"
fi

# Test 3: Generate with minisign, sign with minizign, verify with minisign
log_test "Generate(C) → Sign(Zig) → Verify(C)"
printf "\n\n" | $MINISIGN -G -p "$TEST_DIR/test3.pub" -s "$TEST_DIR/test3.key" >/dev/null 2>&1
printf "\n" | $MINIZIGN -S -s "$TEST_DIR/test3.key" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test3.txt.minisig" >/dev/null 2>&1
if $MINISIGN -V -p "$TEST_DIR/test3.pub" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test3.txt.minisig" >/dev/null 2>&1; then
    log_pass
else
    log_fail "Verification failed"
fi

# Test 4: Generate with minizign, sign with minisign, verify with minizign
log_test "Generate(Zig) → Sign(C) → Verify(Zig)"
printf "\n" | $MINIZIGN -G -s "$TEST_DIR/test4.key" -p "$TEST_DIR/test4.pub" >/dev/null 2>&1
printf "\n" | $MINISIGN -S -s "$TEST_DIR/test4.key" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test4.txt.minisig" >/dev/null 2>&1
if $MINIZIGN -V -p "$TEST_DIR/test4.pub" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test4.txt.minisig" >/dev/null 2>&1; then
    log_pass
else
    log_fail "Verification failed"
fi

# Test 5: Generate with minisign (with password), sign and verify cross-implementation
log_test "Generate(C, encrypted) → Sign(Zig) → Verify(C)"
printf "testpass\ntestpass\n" | $MINISIGN -G -p "$TEST_DIR/test5.pub" -s "$TEST_DIR/test5.key" >/dev/null 2>&1
echo "testpass" | $MINIZIGN -S -s "$TEST_DIR/test5.key" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test5.txt.minisig" >/dev/null 2>&1
if $MINISIGN -V -p "$TEST_DIR/test5.pub" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test5.txt.minisig" >/dev/null 2>&1; then
    log_pass
else
    log_fail "Verification failed"
fi

# Test 6: Generate with minizign (with password), sign and verify cross-implementation
log_test "Generate(Zig, encrypted) → Sign(C) → Verify(Zig)"
echo "testpass" | $MINIZIGN -G -s "$TEST_DIR/test6.key" -p "$TEST_DIR/test6.pub" >/dev/null 2>&1
printf "testpass\n" | $MINISIGN -S -s "$TEST_DIR/test6.key" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test6.txt.minisig" >/dev/null 2>&1
if $MINIZIGN -V -p "$TEST_DIR/test6.pub" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test6.txt.minisig" >/dev/null 2>&1; then
    log_pass
else
    log_fail "Verification failed"
fi

# Test 7: Verify public key format compatibility
log_test "Public key format compatibility"
printf "\n\n" | $MINISIGN -G -p "$TEST_DIR/test7a.pub" -s "$TEST_DIR/test7a.key" >/dev/null 2>&1
printf "\n" | $MINIZIGN -G -s "$TEST_DIR/test7b.key" -p "$TEST_DIR/test7b.pub" >/dev/null 2>&1

# Both should be able to read each other's public keys
if [ -f "$TEST_DIR/test7a.pub" ] && [ -f "$TEST_DIR/test7b.pub" ]; then
    # Check that both public keys have the same structure
    C_LINES=$(wc -l < "$TEST_DIR/test7a.pub")
    ZIG_LINES=$(wc -l < "$TEST_DIR/test7b.pub")
    if [ "$C_LINES" -eq "$ZIG_LINES" ]; then
        log_pass
    else
        log_fail "Public key format differs: C=$C_LINES lines, Zig=$ZIG_LINES lines"
    fi
else
    log_fail "Public key files not created"
fi

# Test 8: Verify signature format compatibility
log_test "Signature format compatibility"
printf "\n\n" | $MINISIGN -G -p "$TEST_DIR/test8.pub" -s "$TEST_DIR/test8.key" >/dev/null 2>&1
printf "\n" | $MINISIGN -S -s "$TEST_DIR/test8.key" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test8a.txt.minisig" >/dev/null 2>&1
printf "\n" | $MINIZIGN -S -s "$TEST_DIR/test8.key" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test8b.txt.minisig" >/dev/null 2>&1

# Both should be able to verify each other's signatures
C_VERIFY=0
ZIG_VERIFY=0

if $MINIZIGN -V -p "$TEST_DIR/test8.pub" -m "$TEST_DIR/test.txt" -o "$TEST_DIR/test8a.txt.minisig" >/dev/null 2>&1; then
    C_VERIFY=1
fi

if $MINISIGN -V -p "$TEST_DIR/test8.pub" -m "$TEST_DIR/test.txt" -x "$TEST_DIR/test8b.txt.minisig" >/dev/null 2>&1; then
    ZIG_VERIFY=1
fi

if [ "$C_VERIFY" -eq 1 ] && [ "$ZIG_VERIFY" -eq 1 ]; then
    log_pass
else
    log_fail "Cross-verification failed (C_sig→Zig: $C_VERIFY, Zig_sig→C: $ZIG_VERIFY)"
fi

# Summary
echo ""
echo "=== Test Summary ==="
echo "Tests run:    $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
if [ "$TESTS_FAILED" -gt 0 ]; then
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    exit 1
else
    echo -e "Tests failed: $TESTS_FAILED"
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
