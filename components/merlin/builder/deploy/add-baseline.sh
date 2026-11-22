#!/bin/bash
# Add another approved XP25 baseline to the MerlinAI Builder. Run as root in the builder VM;
# builder_vm.py add-baseline prepares the disk and the files and calls it.
#
#   add-baseline.sh --name NAME --serial SERIAL --bundle BUNDLE --branch BRANCH --commit SHA \
#                   --image-sha256 HEX --revision TEXT [--symbols DIR]
#
# An installation registered with --baseline NAME is then built and tested on this image: its
# read-only disk (virtio serial SERIAL), a QCOW2 wrapper over it, the source snapshot on BRANCH of
# the immutable baseline repository, and the linker maps of the MerlinAI build installed in it.
# The baseline is recorded in /etc/merlin-builder/baselines.d/NAME.json, which install-builder.sh
# merges into config.json, so it survives a re-bootstrap.
set -euo pipefail

NAME= SERIAL= BUNDLE= BRANCH= COMMIT= IMAGE_SHA= REVISION= SYMBOLS=
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    --serial) SERIAL=$2; shift 2 ;;
    --bundle) BUNDLE=$2; shift 2 ;;
    --branch) BRANCH=$2; shift 2 ;;
    --commit) COMMIT=$2; shift 2 ;;
    --image-sha256) IMAGE_SHA=$2; shift 2 ;;
    --revision) REVISION=$2; shift 2 ;;
    --symbols) SYMBOLS=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ $NAME =~ ^[a-z0-9][a-z0-9-]{0,9}$ ]] || { echo "bad baseline name" >&2; exit 2; }
[[ $SERIAL =~ ^merlin-bl-[a-z0-9-]{1,10}$ ]] || { echo "bad disk serial" >&2; exit 2; }
[[ $BRANCH =~ ^baseline-[a-z0-9-]{1,10}$ ]] || { echo "bad branch" >&2; exit 2; }
[[ $COMMIT =~ ^[0-9a-f]{40}$ && $IMAGE_SHA =~ ^[0-9a-f]{64}$ ]] || { echo "bad commit or hash" >&2; exit 2; }
[ -n "$REVISION" ] && [ -f "$BUNDLE" ] || { echo "missing revision or bundle" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
S=/srv/merlin

# Every baseline disk (serial merlin-bl-*) readable by merlinimg only, like the first one.
grep -qF 'merlin-bl-*' /etc/udev/rules.d/99-merlin-images.rules ||
  echo 'KERNEL=="vd*", ENV{ID_SERIAL}=="merlin-bl-*", GROUP="merlinimg", MODE="0440"' >> /etc/udev/rules.d/99-merlin-images.rules
udevadm control --reload && udevadm trigger --subsystem-match=block && udevadm settle --timeout=30
DEV=/dev/disk/by-id/virtio-$SERIAL
# The trigger is asynchronous: wait for the device and for the rule to have applied.
for i in $(seq 1 30); do [ -e "$DEV" ] && [ "$(stat -L -c %G "$DEV")" = merlinimg ] && break; sleep 1; done
[ -e "$DEV" ] || { echo "missing read-only disk $SERIAL" >&2; exit 1; }
[ "$(stat -L -c %G "$DEV")" = merlinimg ] || { echo "$DEV is not restricted to merlinimg" >&2; exit 1; }

# The source snapshot, on its own branch of the immutable repository.
chmod -R u+w $S/baseline/xp25.git
git -C $S/baseline/xp25.git fetch --quiet "$BUNDLE" "+refs/heads/$BRANCH:refs/heads/$BRANCH"
git -C $S/baseline/xp25.git cat-file -e "$COMMIT^{commit}"
chmod -R a-w $S/baseline/xp25.git

# The image: a QCOW2 wrapper whose backing file is the read-only disk.
W=$S/tools/.work/reference/baseline-$NAME
install -d -o merlinsvc -g merlinsvc -m 0750 $W
if [ ! -e $W/baseline.qcow2 ]; then
  sudo -u merlinsvc qemu-img create -q -f qcow2 -F raw -b "$DEV" $W/baseline.qcow2
  chmod 0444 $W/baseline.qcow2
fi

# Linker maps of the MerlinAI build in this image (crash offset -> function).
SYMDIR=$S/reference/symbols
if [ -n "$SYMBOLS" ]; then
  SYMDIR=$S/reference/symbols-$NAME
  rm -rf "$SYMDIR" && cp -a "$SYMBOLS" "$SYMDIR" && chown -R root:root "$SYMDIR"
fi

install -d -m 0755 /etc/merlin-builder/baselines.d
NAME=$NAME COMMIT=$COMMIT IMAGE=$W/baseline.qcow2 IMAGE_SHA=$IMAGE_SHA REVISION=$REVISION SYMDIR=$SYMDIR python3 - <<'PY'
import json, os
config_path = '/etc/merlin-builder/config.json'
config = json.load(open(config_path))
default = config['baselines'][config['default_baseline']]
entry = dict(default, commit=os.environ['COMMIT'], image=os.environ['IMAGE'], image_format='qcow2',
             image_sha256=os.environ['IMAGE_SHA'], revision=os.environ['REVISION'], symbols=os.environ['SYMDIR'])
name = os.environ['NAME']
with open('/etc/merlin-builder/baselines.d/%s.json' % name, 'w') as f:
    f.write(json.dumps(entry, indent=1) + '\n')
config['baselines'][name] = entry
with open(config_path + '.new', 'w') as f:
    f.write(json.dumps(config, indent=1) + '\n')
os.chmod(config_path + '.new', 0o644)
os.replace(config_path + '.new', config_path)
PY
systemctl restart merlin-builder-api.service merlin-builder-runner.service
sleep 2
curl -sf http://127.0.0.1:8740/merlin/v1/challenge >/dev/null && echo "MERLIN_BASELINE_ADDED name=$NAME commit=$COMMIT"
