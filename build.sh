#!/bin/sh
# Builds "Process Tree.app" (Terminal'de ptree.py'yi açan bir uygulama) ve ~/Applications'a kurar.
# shortcut: Terminal penceresinde çalışır, native pencere değil; gerekirse PyObjC/SwiftUI ile yeniden yazılır.
set -e
cd "$(dirname "$0")"
APP="$HOME/Applications/Process Tree.app"
mkdir -p "$HOME/Applications"
rm -rf "$APP"
osacompile -o "$APP" -e '
set p to POSIX path of (path to resource "ptree.py")
tell application "Terminal"
	activate
	do script "clear; exec python3 " & quoted form of p
end tell'
cp ptree.py "$APP/Contents/Resources/ptree.py"
codesign --force -s - "$APP"  # kopyalama osacompile'ın imzasını bozar, ad-hoc yeniden imzala
echo "Kuruldu: $APP"
