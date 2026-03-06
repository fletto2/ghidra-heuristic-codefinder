#!/bin/bash
# Build HeuristicCodeFinder Ghidra extension without Gradle.
# Usage: ./build.sh /path/to/ghidra_12.0.3_PUBLIC [/path/to/java_home]
#
# Produces dist/ghidra_<ver>_HeuristicCodeFinder.zip

set -e

GHIDRA="${1:?Usage: $0 <GHIDRA_INSTALL_DIR> [JAVA_HOME]}"
JAVA_HOME="${2:-${JAVA_HOME:-}}"

if [ -n "$JAVA_HOME" ]; then
    export PATH="$JAVA_HOME/bin:$PATH"
fi

# Verify tools
command -v javac >/dev/null 2>&1 || { echo "javac not found. Set JAVA_HOME or add to PATH."; exit 1; }
command -v jar   >/dev/null 2>&1 || { echo "jar not found."; exit 1; }
command -v zip   >/dev/null 2>&1 || { echo "zip not found."; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD="$SCRIPT_DIR/build"
DIST="$SCRIPT_DIR/dist"
EXTNAME="HeuristicCodeFinder"

# Read Ghidra version
GHIDRA_VER=$(grep 'application.version' "$GHIDRA/Ghidra/application.properties" | cut -d= -f2 | tr -d ' ')
echo "Building $EXTNAME for Ghidra $GHIDRA_VER"

# Collect classpath from Ghidra JARs
CP=""
for jar in "$GHIDRA"/Ghidra/Framework/*/lib/*.jar "$GHIDRA"/Ghidra/Features/Base/lib/*.jar; do
    [ -f "$jar" ] && CP="$CP:$jar"
done
CP="${CP#:}"

# Compile
rm -rf "$BUILD"
mkdir -p "$BUILD/classes"
echo "Compiling..."
javac -cp "$CP" -d "$BUILD/classes" "$SCRIPT_DIR"/src/main/java/heuristic/*.java
echo "  $(find "$BUILD/classes" -name '*.class' | wc -l) classes compiled"

# Package JAR
mkdir -p "$BUILD/staging/$EXTNAME/lib"
jar cf "$BUILD/staging/$EXTNAME/lib/$EXTNAME.jar" -C "$BUILD/classes" .
cp "$SCRIPT_DIR/extension.properties" "$BUILD/staging/$EXTNAME/"
cp "$SCRIPT_DIR/Module.manifest" "$BUILD/staging/$EXTNAME/"
cp -r "$SCRIPT_DIR/data" "$BUILD/staging/$EXTNAME/"

# Create installable zip
mkdir -p "$DIST"
ZIPNAME="${EXTNAME}.zip"
rm -f "$DIST/$ZIPNAME"
(cd "$BUILD/staging" && zip -r "$DIST/$ZIPNAME" "$EXTNAME/")

echo ""
echo "Built: dist/$ZIPNAME"
echo "Install: Ghidra -> File -> Install Extensions -> + -> select the zip"
