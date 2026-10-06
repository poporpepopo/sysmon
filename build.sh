#!/bin/zsh
# ~/Applications/システムモニタ.app をビルドして入れ直す
set -eu
cd "${0:A:h}"
APP=~/Applications/システムモニタ.app
pkill -x sysmon || true
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -O main.swift -o "$APP/Contents/MacOS/sysmon"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key><string>sysmon</string>
	<key>CFBundleIdentifier</key><string>io.github.poporpepopo.sysmon</string>
	<key>CFBundleName</key><string>システムモニタ</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
codesign --force -s - "$APP"
echo "built: $APP"
