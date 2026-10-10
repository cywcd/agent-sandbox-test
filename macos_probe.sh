#!/bin/bash
set -euo pipefail
probe_root="$(mktemp -d)"
trap 'rm -rf "$probe_root"' EXIT
app="$probe_root/YcodeNativeProbe.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$(dirname "$0")/mcp_write_server.py" "$app/Contents/Resources/"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>YcodeNativeProbe</string>
<key>CFBundleIdentifier</key><string>com.example.ycode.nativeprobe</string>
<key>CFBundleName</key><string>YcodeNativeProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST
cat > "$probe_root/probe.entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
</dict></plist>
PLIST
swiftc "$(dirname "$0")/MacProbe.swift" -o "$app/Contents/MacOS/YcodeNativeProbe"
codesign --force --sign - --entitlements "$probe_root/probe.entitlements" "$app"
codesign -dvvv --entitlements - "$app" 2>&1 | grep -q 'com.apple.security.app-sandbox'
printf unchanged > "$probe_root/outside-marker.txt"
"$app/Contents/MacOS/YcodeNativeProbe" "$(command -v python3)" "$probe_root/outside-marker.txt"
test "$(cat "$probe_root/outside-marker.txt")" = unchanged
