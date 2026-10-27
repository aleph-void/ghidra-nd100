#!/usr/bin/env bash
# Compile src/main/java against the Ghidra install and write lib/C166.jar (what `gradle buildExtension` does,
# without Gradle). Needs GHIDRA_INSTALL_DIR and JAVA_HOME (JDK 21+ with javac; 25 for Ghidra 12.2).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?}"; : "${JAVA_HOME:?}"
OUT=$(mktemp -d "${TMPDIR:-/tmp}/c166jar.XXXXXX"); trap 'rm -rf "$OUT"' EXIT
CP=$(find "$GHIDRA_INSTALL_DIR/Ghidra/Framework" "$GHIDRA_INSTALL_DIR/Ghidra/Features" -name '*.jar' | tr '\n' ':')
"$JAVA_HOME/bin/javac" -nowarn -cp "$CP" -d "$OUT" $(find "$HERE/src/main/java" -name '*.java')
mkdir -p "$HERE/lib"
"$JAVA_HOME/bin/jar" cf "$HERE/lib/C166.jar" -C "$OUT" .
