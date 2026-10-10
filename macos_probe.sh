#!/bin/bash
set -euo pipefail
probe_root="$(mktemp -d)"
outside_root="$(mktemp -d "$HOME/ycode-native-outside.XXXXXX")"
trap 'rm -rf "$probe_root" "$outside_root"' EXIT
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
printf unchanged > "$outside_root/outside-marker.txt"
python_runtime="$(xcrun --find python3)"
"$app/Contents/MacOS/YcodeNativeProbe" "$python_runtime" "$outside_root/outside-marker.txt"
test "$(cat "$outside_root/outside-marker.txt")" = unchanged

# Exercise the same generic broker used by the product, with a container workspace.
native_app="$probe_root/NativeRunner.app"
mkdir -p "$native_app/Contents/MacOS"
cat > "$native_app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>NativeRunner</string>
<key>CFBundleIdentifier</key><string>com.example.nativeprocess.runner</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST
swiftc "$(dirname "$0")/MacRunner.swift" -o "$native_app/Contents/MacOS/NativeRunner"
codesign --force --sign - --entitlements "$probe_root/probe.entitlements" "$native_app"
native_helper="$native_app/Contents/MacOS/NativeRunner"
native_home="$("$native_helper" --home)"
mkdir -p "$native_home/Documents/worktrees"
native_workspace="$(mktemp -d "$native_home/Documents/worktrees/probe.XXXXXX")"
trap 'rm -rf "$probe_root" "$outside_root" "$native_workspace"' EXIT
cp "$(dirname "$0")/mcp_write_server.py" "$native_workspace/server.py"
"$python_runtime" - "$native_helper" "$native_workspace" "$python_runtime" "$outside_root/outside-marker.txt" <<'PY'
import json,pathlib,subprocess,sys
helper,workspace,python,outside=sys.argv[1:]
requests=[{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}},
          {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_sample","arguments":{"path":"mcp-broker.txt"}}},
          {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_boundary","arguments":{"path":outside}}}]
result=subprocess.run([helper,"--run",workspace,"-",python,str(pathlib.Path(workspace)/"server.py")],input="".join(json.dumps(r)+"\n" for r in requests),capture_output=True,text=True,timeout=30)
assert result.returncode==0,result.stderr
responses={r['id']:r['result'] for r in map(json.loads,result.stdout.splitlines())}
assert responses[0]['serverInfo']['name']=='native-write-probe'
assert pathlib.Path(workspace,'mcp-broker.txt').read_text()=='mcp'
assert all(json.loads(responses[2]['content'][0]['text']).values())
refused=subprocess.run([helper,"--run",str(pathlib.Path(outside).parent),"-",python,"-c","open('escaped.txt','w').write('bad')"],capture_output=True,text=True,timeout=10)
assert refused.returncode==125
print(json.dumps({'native_broker_mcp':True,'native_broker_outside_read_and_network_denied':True,'unauthorized_workspace_denied':True}))
PY
