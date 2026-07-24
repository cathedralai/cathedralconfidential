#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: runtime/smoke-container.sh IMAGE" >&2
  exit 2
fi

smoke_root="$(mktemp -d)"
trap 'rm -rf "$smoke_root"' EXIT HUP INT TERM
mkdir -m 0700 "$smoke_root/outputs"
python3 -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack("<4f",1,-2,3.5,4)); open(sys.argv[2],"wb").write(struct.pack("<4f",2,.5,-1,3))' "$smoke_root/input.bin" "$smoke_root/model.bin"
chmod 0600 "$smoke_root/input.bin" "$smoke_root/model.bin"

docker run --rm --platform linux/amd64 --entrypoint /bin/sh "$1" -c 'test -x /usr/bin/python3 && test -x /usr/bin/unshare && test -x /usr/bin/setpriv && test -d /work'
if docker run --rm --platform linux/amd64 --entrypoint /usr/bin/python3 \
  -e CATHEDRAL_INPUT_DIR=/work -e CATHEDRAL_OUTPUT_DIR=/work/outputs \
  -v "$smoke_root:/work" "$1" /opt/cathedral/bin/cathedral-job; then
  echo "fixed workload unexpectedly succeeded without an attached H100" >&2
  exit 1
fi
test ! -e "$smoke_root/outputs/result.json"
