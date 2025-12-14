#!/bin/bash

# ================= CONFIGURATION =================
# Path to kem.c relative to this script
TARGET_FILE="../crypto_kem/ml-kem-768/clean/kem.c"

# Code string for Secure Mode (FO-Transform Active)
CODE_SECURE="fail = PQCLEAN_MLKEM768_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);"

# Code string for Vulnerable Mode (FO-Transform Bypassed)
# We use simple 0 assignment.
CODE_VULN="fail = 0; // VULNERABILITY INJECTED (FO-Bypass)"
# =================================================

# Check if the target file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[Error] Cannot find kem.c at $TARGET_FILE"
    exit 1
fi

function set_secure() {
    echo "[System] Switching to SECURE mode (Active FO-Transform)..."
    # Use | as delimiter to avoid conflict with / in file paths
    # Match any line containing "fail =" and replace with secure code
    sed -i "s|fail =.*;|$CODE_SECURE|" "$TARGET_FILE"
}

function set_vuln() {
    echo "[System] Switching to VULNERABLE mode (Bypassing FO-Transform)..."
    # Use | as delimiter to avoid conflict with // in comments
    # Match any line containing "fail =" and replace with vulnerable code
    sed -i "s|fail =.*;|$CODE_VULN|" "$TARGET_FILE"
}

# Parse command line arguments
if [ "$1" == "vuln" ]; then
    set_vuln
elif [ "$1" == "secure" ]; then
    set_secure
else
    echo "Usage: ./switch_mode.sh [vuln|secure]"
    echo "  vuln   : Disable FO check (fail = 0)"
    echo "  secure : Enable FO check (fail = verify)"
    exit 1
fi

# Automatically recompile
echo "[Make] Recompiling project..."
make clean > /dev/null 2>&1
make all > /dev/null

if [ $? -eq 0 ]; then
    echo "[Success] Server is rebuilt and ready."
else
    echo "[Error] Compilation failed."
fi