#!/usr/bin/env python3
"""Create and maintain the MerlinAI Builder VM (a separate KVM guest) from the host.

  builder_vm.py provision --dir DIR --cloud-image IMG --baseline-image QCOW2 --buildvm-image QCOW2
                          [--name MerlinAI-Builder] [--memory-mb 8192] [--cpus 6] [--data-gb 160]
                          [--network default] [--gateway 192.168.122.1]
      fresh VM directory: system disk (Ubuntu cloud image), sparse data disk, read-only
      reflink copies of the two XP25 image chains, cloud-init seed, SSH key for the
      administrator; defines the merlin-builder network filter and the domain, starts it.
  builder_vm.py bootstrap --dir DIR --repo REPO --commit COMMIT --baseline-image-sha256 H --revision NAME
                          --toolchain DIR --reference DIR
      waits for SSH, copies a source-only snapshot of REPO at COMMIT (no Source/),
      the toolchain and reference files, and runs install-builder.sh in the VM.
  builder_vm.py register --dir DIR --installation ID | --agent NAME --installations ID[,ID]
      creates credentials on the builder and prints them once.
  builder_vm.py ssh --dir DIR -- COMMAND...

Nothing here depends on the builder running on this host except the read-only
image disks it attaches; a remote builder gets the same disks by other means.
The XP25 images are attached read-only (libvirt <readonly/>), so neither the
builder nor anything it runs can change them."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
VIRSH = ['virsh', '-c', 'qemu:///system']

USER_DATA = """#cloud-config
hostname: merlin-builder
users:
  - name: merlinadmin
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - {key}
ssh_pwauth: false
disable_root: true
package_update: true
package_upgrade: false
packages: [qemu-system-x86, qemu-utils, ntfs-3g, xorriso, python3, python3-pil, git, fuse3, genisoimage, curl, libisl23, libmpc3, libmpfr6]
fs_setup:
  - label: merlin-data
    filesystem: ext4
    device: /dev/vdb
    partition: none
mounts:
  - [LABEL=merlin-data, /srv/merlin, ext4, "defaults,nofail", "0", "2"]
runcmd:
  - [mkdir, -p, /srv/merlin/incoming]
  - [chown, merlinadmin, /srv/merlin/incoming]
  - [sh, -c, "echo MERLIN_CLOUD_INIT_DONE > /dev/ttyS0"]
"""

DOMAIN = """<domain type='kvm'>
  <name>{name}</name>
  <description>MerlinAI Builder: investigates XP25 problems, rebuilds XP25 components and tests candidate images in nested, NIC-less VMs. Created by components/merlin/builder/deploy/builder_vm.py.</description>
  <memory unit='MiB'>{memory}</memory>
  <vcpu>{cpus}</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough' check='none' migratable='off'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' discard='unmap'/>
      <source file='{dir}/system.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' discard='unmap'/>
      <source file='{dir}/data.qcow2'/>
      <target dev='vdb' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{baseline}'/>
      <target dev='vdc' bus='virtio'/>
      <readonly/>
      <serial>merlin-baseline</serial>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{buildvm}'/>
      <target dev='vdd' bus='virtio'/>
      <readonly/>
      <serial>merlin-buildvm</serial>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{dir}/seed.iso'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='{network}'/>
      <model type='virtio'/>
      <filterref filter='merlin-builder'>
        <parameter name='GATEWAY_IP' value='{gateway}'/>
        <parameter name='API_PORT' value='8740'/>
      </filterref>
    </interface>
    <serial type='file'>
      <source path='{dir}/console.log'/>
      <target port='0'/>
    </serial>
    <console type='file'>
      <source path='{dir}/console.log'/>
      <target type='serial' port='0'/>
    </console>
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
  </devices>
</domain>
"""


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, text=True, capture_output=True, **kw)


def copy_chain(top, into):
    """Reflink-copy an image and its backing chain into a directory and point the copies at each other."""
    into.mkdir(parents=True)
    info = json.loads(run(['qemu-img', 'info', '-U', '--backing-chain', '--output=json', top]).stdout)
    copies = []
    for n, layer in enumerate(info):
        dst = into / ('%02d-%s' % (n, Path(layer['filename']).name))
        run(['cp', '--reflink=always', layer['filename'], dst])
        dst.chmod(0o644)
        copies.append((dst, layer.get('format', 'qcow2')))
    for (dst, _), (below, fmt) in zip(copies, copies[1:]):
        run(['qemu-img', 'rebase', '-u', '-F', fmt, '-b', below, dst])
    for dst, _ in copies:
        dst.chmod(0o444)
    return copies[0][0], [str(d) for d, _ in copies]


def provision(args):
    d = args.dir.resolve()
    d.mkdir(parents=True, exist_ok=False)
    (d / 'ssh').mkdir(mode=0o700)
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'merlin-builder-admin', '-f', d / 'ssh/id_ed25519'])
    key = (d / 'ssh/id_ed25519.pub').read_text().strip()
    run(['qemu-img', 'convert', '-O', 'qcow2', args.cloud_image, d / 'system.qcow2'])
    run(['qemu-img', 'resize', d / 'system.qcow2', '24G'])
    run(['qemu-img', 'create', '-f', 'qcow2', d / 'data.qcow2', '%dG' % args.data_gb])
    baseline, baseline_chain = copy_chain(args.baseline_image.resolve(), d / 'ro-baseline')
    buildvm, buildvm_chain = copy_chain(args.buildvm_image.resolve(), d / 'ro-buildvm')
    seed = d / 'seed'
    seed.mkdir()
    (seed / 'user-data').write_text(USER_DATA.format(key=key))
    (seed / 'meta-data').write_text('instance-id: merlin-builder-%d\nlocal-hostname: merlin-builder\n' % int(time.time()))
    run(['genisoimage', '-quiet', '-output', d / 'seed.iso', '-volid', 'cidata', '-joliet', '-rock', seed / 'user-data', seed / 'meta-data'])
    defined = subprocess.run(VIRSH + ['nwfilter-list'], capture_output=True, text=True).stdout
    if ' merlin-builder ' not in defined + ' ':
        run(VIRSH + ['nwfilter-define', HERE / 'merlin-builder.nwfilter.xml'])
    xml = DOMAIN.format(name=args.name, memory=args.memory_mb, cpus=args.cpus, dir=d, baseline=baseline, buildvm=buildvm,
                        network=args.network, gateway=args.gateway)
    (d / 'domain.xml').write_text(xml)
    run(VIRSH + ['define', d / 'domain.xml'])
    run(VIRSH + ['start', args.name])
    record = {'name': args.name, 'dir': str(d), 'cloud_image': str(args.cloud_image), 'baseline_chain': baseline_chain,
              'buildvm_chain': buildvm_chain, 'memory_mb': args.memory_mb, 'cpus': args.cpus, 'data_gb': args.data_gb,
              'network': args.network, 'gateway': args.gateway, 'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    (d / 'builder-vm.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps(record, indent=1))


def address(d, name, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(VIRSH + ['domifaddr', name], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == 'ipv4':
                return parts[3].split('/')[0]
        time.sleep(5)
    raise TimeoutError('the builder VM got no address')


def ssh_base(d, ip):
    return ['ssh', '-i', str(d / 'ssh/id_ed25519'), '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile=' + str(d / 'ssh/known_hosts'), '-o', 'ConnectTimeout=10', 'merlinadmin@' + ip]


def wait_ssh(d, ip, timeout=1200):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(ssh_base(d, ip) + ['cloud-init status --wait >/dev/null 2>&1; test -d /srv/merlin/incoming && echo ready'],
                           capture_output=True, text=True)
        if 'ready' in r.stdout:
            return
        time.sleep(10)
    raise TimeoutError('SSH or cloud-init did not finish')


def snapshot_bundle(repo, commit, out):
    """A source-only snapshot of REPO at COMMIT (Source/ and .work/ excluded) as a one-commit git bundle."""
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / 'tree'
        tree.mkdir()
        archive = Path(tmp) / 'src.tar'
        run(['git', '-C', repo, 'archive', '--format=tar', '-o', archive, commit, '--', '.', ':(exclude)Source'])
        run(['tar', '-x', '--no-same-owner', '--no-same-permissions', '-f', archive, '-C', tree])
        env = dict(os.environ, GIT_AUTHOR_NAME='MerlinAI baseline', GIT_AUTHOR_EMAIL='merlin@xp25.invalid',
                   GIT_COMMITTER_NAME='MerlinAI baseline', GIT_COMMITTER_EMAIL='merlin@xp25.invalid',
                   GIT_AUTHOR_DATE='2026-11-21T00:00:00Z', GIT_COMMITTER_DATE='2026-11-21T00:00:00Z')
        run(['git', 'init', '-q', '-b', 'baseline', tree])
        run(['git', '-C', tree, 'add', '-A'], env=env)
        run(['git', '-C', tree, 'commit', '-q', '-m', 'XP25 approved baseline for MerlinAI (source snapshot of %s without Source/)' % commit], env=env)
        snap = run(['git', '-C', tree, 'rev-parse', 'HEAD']).stdout.strip()
        run(['git', '-C', tree, 'bundle', 'create', '-q', out, 'baseline'])
        return snap


def bootstrap(args):
    d = args.dir.resolve()
    record = json.loads((d / 'builder-vm.json').read_text())
    ip = address(d, record['name'])
    wait_ssh(d, ip)
    bundle = d / 'baseline.bundle'
    snap = snapshot_bundle(args.repo.resolve(), args.commit, bundle)
    base = ssh_base(d, ip)
    target = 'merlinadmin@' + ip
    scp = ['scp', '-q', '-i', str(d / 'ssh/id_ed25519'), '-o', 'UserKnownHostsFile=' + str(d / 'ssh/known_hosts'), '-r']
    run(scp + [bundle, target + ':/srv/merlin/incoming/baseline.bundle'])
    # Fresh incoming directories: copies of read-only reference files cannot be overwritten in place.
    run(base + ['chmod -R u+w /srv/merlin/incoming 2>/dev/null; rm -rf /srv/merlin/incoming/toolchains /srv/merlin/incoming/reference; '
                'mkdir -p /srv/merlin/incoming/toolchains /srv/merlin/incoming/reference'])
    run(scp + [args.toolchain.resolve(), target + ':/srv/merlin/incoming/toolchains/'])
    for child in sorted(args.reference.resolve().iterdir()):
        run(scp + [child, target + ':/srv/merlin/incoming/reference/'])
    run(scp + [HERE / 'install-builder.sh', target + ':/srv/merlin/incoming/install-builder.sh'])
    r = subprocess.run(base + ['sudo bash /srv/merlin/incoming/install-builder.sh --bundle /srv/merlin/incoming/baseline.bundle '
                               '--commit %s --baseline-image-sha256 %s --revision %s' % (snap, args.baseline_image_sha256, args.revision)],
                       capture_output=True, text=True)
    (d / 'bootstrap.log').write_text(r.stdout + r.stderr)
    record.update({'ip': ip, 'baseline_snapshot_commit': snap, 'source_commit': args.commit,
                   'baseline_image_sha256': args.baseline_image_sha256, 'revision': args.revision,
                   'bootstrapped': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'ready': 'MERLIN_BUILDER_READY' in r.stdout})
    (d / 'builder-vm.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({k: record[k] for k in ('ip', 'baseline_snapshot_commit', 'ready')}))
    return 0 if record['ready'] else 1


def register(args):
    d = args.dir.resolve()
    record = json.loads((d / 'builder-vm.json').read_text())
    ip = record['ip']
    cmd = 'cd /srv/merlin/tools/components/merlin/builder && sudo -u merlinsvc python3 -m merlin_builder '
    if args.installation:
        cmd += 'register-installation ' + args.installation + ' --config /etc/merlin-builder/config.json'
    else:
        cmd += 'register-agent ' + args.agent + ' ' + ' '.join(args.installations.split(',')) + ' --config /etc/merlin-builder/config.json'
    r = run(ssh_base(d, ip) + [cmd])
    print(r.stdout.strip())


def ssh(args):
    d = args.dir.resolve()
    record = json.loads((d / 'builder-vm.json').read_text())
    return subprocess.call(ssh_base(d, record['ip']) + args.command)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('provision')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--cloud-image', type=Path, required=True)
    p.add_argument('--baseline-image', type=Path, required=True)
    p.add_argument('--buildvm-image', type=Path, required=True)
    p.add_argument('--name', default='MerlinAI-Builder')
    p.add_argument('--memory-mb', type=int, default=8192)
    p.add_argument('--cpus', type=int, default=6)
    p.add_argument('--data-gb', type=int, default=160)
    p.add_argument('--network', default='default')
    p.add_argument('--gateway', default='192.168.122.1')
    p = sub.add_parser('bootstrap')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--baseline-image-sha256', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--toolchain', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    p = sub.add_parser('register')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--installation')
    p.add_argument('--agent')
    p.add_argument('--installations', default='')
    p = sub.add_parser('ssh')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    return {'provision': provision, 'bootstrap': bootstrap, 'register': register, 'ssh': ssh}[args.action](args) or 0


if __name__ == '__main__':
    sys.exit(main())
