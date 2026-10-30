#!/bin/sh
EXT="$1"
if [ -z "$EXT" ]; then
  echo "usage: sh $0 <extension_id>"
  exit 1
fi

WORK="/tmp/ext_$EXT"
mkdir -p "$WORK/src"
cd "$WORK" || exit 1

URL="https://clients2.google.com/service/update2/crx?response=redirect&prodversion=130.0&acceptformat=crx2,crx3&x=id%3D${EXT}%26uc"

if ! curl -fL -o ext.crx "$URL"; then
  echo "download failed"
  exit 1
fi

if [ "$(head -c 4 ext.crx)" != "Cr24" ]; then
  echo "not a CRX file"
  exit 1
fi

VER=$(od -An -t u4 -j 4 -N 4 ext.crx | tr -d ' ')
HL=$(od -An -t u4 -j 8 -N 4 ext.crx | tr -d ' ')

if [ "$VER" = "3" ]; then
  OFF=$((12 + HL))
elif [ "$VER" = "2" ]; then
  SL=$(od -An -t u4 -j 12 -N 4 ext.crx | tr -d ' ')
  OFF=$((16 + HL + SL))
else
  echo "unsupported CRX version $VER"
  exit 1
fi

tail -c +$((OFF + 1)) ext.crx > ext.zip
tar -xf ext.zip -C src || exit 1

cat src/manifest.json
echo
echo "--- JS files ---"
find src -name '*.js' -ls