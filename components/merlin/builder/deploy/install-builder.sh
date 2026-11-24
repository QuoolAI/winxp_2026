#!/bin/bash
# Set up (or update) the MerlinAI Builder inside its own VM. Run as root on the builder.
#
#   install-builder.sh --bundle /srv/merlin/incoming/baseline.bundle --commit <sha> \
#                      --baseline-image-sha256 <hex> --revision <name> \
#                      [--tools-bundle /srv/merlin/incoming/tools.bundle --tools-commit <sha>]
#
# --commit is the default baseline's source (what its image was built from); the builder's own
# scripts come from --tools-commit when given, so they can be updated without changing a baseline.
#
# Expects, prepared by the host's provision-builder-vm.sh:
#   /dev/disk/by-id/virtio-merlin-baseline   the approved XP25 system image (read-only disk)
#   /dev/disk/by-id/virtio-merlin-buildvm    the frozen NT 5.1 build VM (read-only disk)
#   /srv/merlin/incoming/                    baseline git bundle, MinGW toolchain, reference files
# It creates the unprivileged service account merlinsvc, the immutable baseline
# repository, the tools checkout, QCOW2 wrappers for the two read-only disks,
# the configuration and the two services. It never stores model-provider keys:
# those are added by the administrator as /etc/merlin-builder/provider.key.
set -euo pipefail

BUNDLE= COMMIT= IMAGE_SHA= REVISION= TOOLS_BUNDLE= TOOLS_COMMIT=
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE=$2; shift 2 ;;
    --commit) COMMIT=$2; shift 2 ;;
    --baseline-image-sha256) IMAGE_SHA=$2; shift 2 ;;
    --revision) REVISION=$2; shift 2 ;;
    --tools-bundle) TOOLS_BUNDLE=$2; shift 2 ;;
    --tools-commit) TOOLS_COMMIT=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ -n "$BUNDLE" ] && [ -n "$COMMIT" ] && [ -n "$IMAGE_SHA" ] && [ -n "$REVISION" ] || { echo "missing options" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

S=/srv/merlin
# Runtime libraries of the MinGW cross-compiler copied from the host (cc1 links libisl, libmpc, libmpfr).
DEBIAN_FRONTEND=noninteractive apt-get install -y -q libisl23 libmpc3 libmpfr6 >/dev/null
id merlinsvc >/dev/null 2>&1 || useradd --system --home-dir $S/data --shell /usr/sbin/nologin merlinsvc
getent group merlinimg >/dev/null || groupadd --system merlinimg
usermod -aG kvm,merlinimg merlinsvc
install -d -o root -g root -m 0755 $S $S/baseline $S/reference $S/toolchains
install -d -o merlinsvc -g merlinsvc -m 0750 $S/data

# Jobs need unprivileged user namespaces (network-less sandboxes) and QEMU with KVM.
echo 'kernel.apparmor_restrict_unprivileged_userns=0' > /etc/sysctl.d/60-merlin-builder.conf
sysctl -q -p /etc/sysctl.d/60-merlin-builder.conf || true

# The two read-only disks: readable by merlinimg only (the host attaches them read-only as well).
# After 60-persistent-storage.rules, which sets ID_SERIAL from the virtio serial.
rm -f /etc/udev/rules.d/60-merlin-images.rules
cat > /etc/udev/rules.d/99-merlin-images.rules <<'RULES'
KERNEL=="vd*", ENV{ID_SERIAL}=="merlin-baseline", GROUP="merlinimg", MODE="0440"
KERNEL=="vd*", ENV{ID_SERIAL}=="merlin-buildvm", GROUP="merlinimg", MODE="0440"
KERNEL=="vd*", ENV{ID_SERIAL}=="merlin-bl-*", GROUP="merlinimg", MODE="0440"
RULES
udevadm control --reload && udevadm trigger --subsystem-match=block
for d in merlin-baseline merlin-buildvm; do
  for i in $(seq 1 30); do [ -e /dev/disk/by-id/virtio-$d ] && break; sleep 1; done
  [ -e /dev/disk/by-id/virtio-$d ] || { echo "missing read-only disk $d" >&2; exit 1; }
done

# The immutable baseline repository (bare, root-owned, read-only for the services).
if [ ! -d $S/baseline/xp25.git ]; then
  git clone --quiet --bare "$BUNDLE" $S/baseline/xp25.git
fi
chmod -R u+w $S/baseline/xp25.git
git -C $S/baseline/xp25.git fetch --quiet "$BUNDLE" "+refs/heads/*:refs/heads/*" || true
git -C $S/baseline/xp25.git symbolic-ref HEAD refs/heads/baseline
# The baseline and the tools are root-owned and read by the merlinsvc runner: tell Git that is intended.
git config --system --get-all safe.directory | grep -qx $S/baseline/xp25.git || git config --system --add safe.directory $S/baseline/xp25.git
git config --system --get-all safe.directory | grep -qx $S/tools || git config --system --add safe.directory $S/tools
git -C $S/baseline/xp25.git cat-file -e "$COMMIT^{commit}"
if [ -n "$TOOLS_BUNDLE" ]; then
  git -C $S/baseline/xp25.git fetch --quiet "$TOOLS_BUNDLE" "+refs/heads/tools:refs/heads/tools"
  git -C $S/baseline/xp25.git cat-file -e "$TOOLS_COMMIT^{commit}"
fi
TOOLS_COMMIT=${TOOLS_COMMIT:-$COMMIT}
chmod -R a-w $S/baseline/xp25.git

# The tools checkout: the builder's own scripts at the approved commit. Its .work holds build-VM runs.
rm -rf $S/tools.new
git clone --quiet $S/baseline/xp25.git $S/tools.new
git -C $S/tools.new checkout --quiet "$TOOLS_COMMIT"
if [ -d $S/tools/.work ]; then mv $S/tools/.work $S/tools.new/.work; fi
rm -rf $S/tools && mv $S/tools.new $S/tools
install -d -o merlinsvc -g merlinsvc -m 0750 $S/tools/.work $S/tools/.work/boot-debug-20261022
install -d -o merlinsvc -g merlinsvc -m 0750 $S/tools/.work/reference $S/tools/.work/reference/xp25-baseline $S/tools/.work/reference/build-vm
chown -R root:root $S/tools && chown -R merlinsvc:merlinsvc $S/tools/.work

# QCOW2 wrappers whose backing files are the read-only disks: overlays on them cost only their own changes.
B=$S/tools/.work/reference/xp25-baseline/baseline.qcow2
V=$S/tools/.work/reference/build-vm/disk.qcow2
for pair in "$B:/dev/disk/by-id/virtio-merlin-baseline" "$V:/dev/disk/by-id/virtio-merlin-buildvm"; do
  file=${pair%%:*}; dev=${pair#*:}
  if [ ! -e "$file" ]; then
    sudo -u merlinsvc qemu-img create -q -f qcow2 -F raw -b "$dev" "$file"
    chmod 0444 "$file"
  fi
done

# Toolchain and reference files copied in by the host (MinGW for checks, guest system DLLs for import
# checks, the verified MP kernel and HAL for two-vCPU tests, linker maps of the baseline's MerlinAI build).
for d in toolchains reference; do
  if [ -d $S/incoming/$d ]; then cp -a $S/incoming/$d/. $S/$d/; fi
done
# The NT reference tree is a read-only image mounted at $S/reference/nt (builder_vm.py reference-source); it is
# already root-owned and cannot be changed, so it is left out.
chown -R root:root $S/toolchains
for f in $S/reference/*; do [ "$f" = "$S/reference/nt" ] || chown -R root:root "$f"; done

install -d -m 0755 /etc/merlin-builder
cat > /etc/merlin-builder/config.json <<CONFIG
{
 "listen": "0.0.0.0:8740",
 "data": "$S/data",
 "log": "$S/data/api.jsonl",
 "tools": "$S/tools",
 "toolchain": "$S/toolchains/mingw-binutils/usr/bin",
 "default_baseline": "xp25-m9",
 "baselines": {
  "xp25-m9": {
   "repository": "$S/baseline/xp25.git",
   "commit": "$COMMIT",
   "image": "$B",
   "image_format": "qcow2",
   "image_sha256": "$IMAGE_SHA",
   "revision": "$REVISION",
   "build_vm": "$V",
   "guest_modules": "$S/reference/guest-modules/WINDOWS/system32",
   "symbols": "$S/reference/symbols",
   "mp_kernel": "$S/reference/kernel/ntkrnlmp.exe",
   "mp_hal": "$S/reference/kernel/halmacpi.dll"
  }
 },
 "provider": $( [ -f /etc/merlin-builder/provider.json ] && cat /etc/merlin-builder/provider.json || echo '{"kind": "offline"}' ),
$( [ -d $S/reference/nt ] && echo " \"reference_source\": \"$S/reference/nt\"," )
 "test_modes": ["up", "mp", "tcg"],
 "sandbox_network": true,
 "limits": {"max_request_bytes": 1048576, "max_dump_bytes": 8388608, "max_reports_per_installation": 500,
            "installation_quota_bytes": 268435456, "max_open_jobs_per_installation": 2, "job_disk_reserve_gb": 15}
}
CONFIG
# Baselines added later (add-baseline.sh) stay configured.
if ls /etc/merlin-builder/baselines.d/*.json >/dev/null 2>&1; then
  python3 - <<'PY'
import glob, json, os
path = '/etc/merlin-builder/config.json'
config = json.load(open(path))
for f in sorted(glob.glob('/etc/merlin-builder/baselines.d/*.json')):
    config['baselines'][os.path.basename(f)[:-5]] = json.load(open(f))
open(path, 'w').write(json.dumps(config, indent=1) + '\n')
PY
fi
chmod 0644 /etc/merlin-builder/config.json
if [ -f /etc/merlin-builder/provider.key ]; then chown root:merlinsvc /etc/merlin-builder/provider.key; chmod 0640 /etc/merlin-builder/provider.key; fi

install -m 0644 $S/tools/components/merlin/builder/deploy/merlin-builder-api.service /etc/systemd/system/
install -m 0644 $S/tools/components/merlin/builder/deploy/merlin-builder-runner.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now merlin-builder-api.service merlin-builder-runner.service
systemctl restart merlin-builder-api.service merlin-builder-runner.service
sleep 2
curl -sf http://127.0.0.1:8740/merlin/v1/challenge >/dev/null && echo "MERLIN_BUILDER_READY commit=$COMMIT tools=$TOOLS_COMMIT"
