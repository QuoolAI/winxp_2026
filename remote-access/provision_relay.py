#!/usr/bin/env python3
"""Create (or find) the AWS end of the XP25 reverse tunnel next to an existing
Guacamole deployment, using only the AWS CLI.

  - EC2 role + instance profile with AmazonSSMManagedInstanceCore only.
  - Security group: inbound VNC port only from the Guacamole task's group;
    outbound HTTPS only (SSM and security updates).
  - t4g.nano Amazon Linux 2023 relay: IMDSv2 only (hop limit 1), encrypted
    root volume, no key pair, termination protection, configured by
    relay-user-data.sh. It is deliberately not tagged MEAEnvironment, because
    the MEA worker terminates tagged instances that have no desktop lease.
  - IAM user that may only open AWS-StartSSHSession sessions to that instance.

Every step reuses an existing resource with the same name. The record written
to --record has no secrets; the access key, when one is created, goes only to
--access-key-out (mode 0600).
usage: provision_relay.py --guacamole-sg SG --subnet SUBNET --public-key FILE
       --record OUT.json [--access-key-out FILE] [--profile P] [--region R]"""
import argparse, json, os, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--profile', help='AWS CLI profile (default: the usual AWS environment)')
    p.add_argument('--region', default='us-west-2')
    p.add_argument('--name', default='mea-staging-xp25-relay')
    p.add_argument('--user', default='mea-staging-xp25-tunnel')
    p.add_argument('--guacamole-sg', required=True)
    p.add_argument('--subnet', required=True)
    p.add_argument('--public-key', type=Path, required=True)
    p.add_argument('--vnc-port', type=int, default=5900)
    p.add_argument('--instance-type', default='t4g.nano')
    p.add_argument('--record', type=Path, required=True)
    p.add_argument('--access-key-out', type=Path)
    a = p.parse_args()
    record = {'name': a.name, 'region': a.region, 'vnc_port': a.vnc_port, 'steps': []}

    def aws(*args, check=True):
        profile = ['--profile', a.profile] if a.profile else []
        r = subprocess.run(['aws', *profile, '--region', a.region, '--output', 'json', *args],
                           capture_output=True, text=True)
        if check and r.returncode:
            raise SystemExit(f'aws {args[0]} {args[1]} failed: {r.stderr.strip()}')
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None

    def step(name, value):
        record['steps'].append({'step': name, 'value': value})
        print(f'{name}: {value}', flush=True)

    account = aws('sts', 'get-caller-identity')['Account']
    subnet = aws('ec2', 'describe-subnets', '--subnet-ids', a.subnet)['Subnets'][0]
    vpc = subnet['VpcId']
    tags = [{'Key': 'Name', 'Value': a.name}, {'Key': 'Project', 'Value': 'MiseEnAbyme'},
            {'Key': 'Component', 'Value': 'xp25-relay'}, {'Key': 'ManagedBy', 'Value': 'xp25-remote-access'}]

    # 1. Instance role and profile.
    trust = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'},
                                                               'Action': 'sts:AssumeRole'}]})
    if not aws('iam', 'get-role', '--role-name', a.name, check=False):
        aws('iam', 'create-role', '--role-name', a.name, '--assume-role-policy-document', trust, '--tags', json.dumps(tags))
    aws('iam', 'attach-role-policy', '--role-name', a.name, '--policy-arn', 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')
    if not aws('iam', 'get-instance-profile', '--instance-profile-name', a.name, check=False):
        aws('iam', 'create-instance-profile', '--instance-profile-name', a.name)
        aws('iam', 'add-role-to-instance-profile', '--instance-profile-name', a.name, '--role-name', a.name)
        time.sleep(15)  # instance profiles take a moment to become usable by RunInstances
    step('instance_profile', a.name)

    # 2. Security group.
    groups = aws('ec2', 'describe-security-groups', '--filters', f'Name=vpc-id,Values={vpc}', f'Name=group-name,Values={a.name}')['SecurityGroups']
    if groups:
        sg = groups[0]['GroupId']
    else:
        sg = aws('ec2', 'create-security-group', '--group-name', a.name, '--vpc-id', vpc,
                 '--description', 'XP25 VNC relay: VNC from Guacamole only, HTTPS out only',
                 '--tag-specifications', json.dumps([{'ResourceType': 'security-group', 'Tags': tags}]))['GroupId']
        aws('ec2', 'authorize-security-group-ingress', '--group-id', sg, '--ip-permissions', json.dumps([{
            'IpProtocol': 'tcp', 'FromPort': a.vnc_port, 'ToPort': a.vnc_port,
            'UserIdGroupPairs': [{'GroupId': a.guacamole_sg, 'Description': 'guacd to the XP25 reverse tunnel'}]}]))
        aws('ec2', 'revoke-security-group-egress', '--group-id', sg, '--ip-permissions', json.dumps([{
            'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]))
        aws('ec2', 'authorize-security-group-egress', '--group-id', sg, '--ip-permissions', json.dumps([{
            'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSM and security updates'}]}]))
    step('security_group', sg)

    # 3. Instance.
    found = aws('ec2', 'describe-instances', '--filters', f'Name=tag:Name,Values={a.name}',
                'Name=instance-state-name,Values=pending,running,stopping,stopped')['Reservations']
    if found:
        instance = found[0]['Instances'][0]['InstanceId']
    else:
        key = a.public_key.read_text().strip()
        if not key.startswith('ssh-ed25519 ') or '\n' in key or "'" in key:
            raise SystemExit('expected one ssh-ed25519 public key')
        user_data = (HERE / 'relay-user-data.sh').read_text().replace('@TUNNEL_PUBLIC_KEY@', key).replace('@VNC_PORT@', str(a.vnc_port))
        ami = aws('ssm', 'get-parameter', '--name', '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64')['Parameter']['Value']
        record['ami'] = ami
        instance = aws('ec2', 'run-instances', '--image-id', ami, '--instance-type', a.instance_type,
                       '--subnet-id', a.subnet, '--security-group-ids', sg,
                       '--iam-instance-profile', f'Name={a.name}', '--user-data', user_data,
                       '--metadata-options', 'HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled',
                       '--block-device-mappings', json.dumps([{'DeviceName': '/dev/xvda', 'Ebs': {
                           'VolumeSize': 8, 'VolumeType': 'gp3', 'Encrypted': True, 'DeleteOnTermination': True}}]),
                       '--disable-api-termination', '--associate-public-ip-address',
                       '--tag-specifications', json.dumps([{'ResourceType': 'instance', 'Tags': tags},
                                                           {'ResourceType': 'volume', 'Tags': tags}]))['Instances'][0]['InstanceId']
    aws('ec2', 'wait', 'instance-running', '--instance-ids', instance)
    described = aws('ec2', 'describe-instances', '--instance-ids', instance)['Reservations'][0]['Instances'][0]
    record.update(instance_id=instance, private_ip=described['PrivateIpAddress'], ami=described['ImageId'],
                  instance_type=described['InstanceType'])
    step('instance', f"{instance} {described['PrivateIpAddress']}")

    # 4. SSM registration and first-boot result.
    for _ in range(60):
        info = aws('ssm', 'describe-instance-information', '--filters', f'Key=InstanceIds,Values={instance}')['InstanceInformationList']
        if info and info[0]['PingStatus'] == 'Online':
            break
        time.sleep(10)
    else:
        raise SystemExit('relay did not register with SSM')
    command = aws('ssm', 'send-command', '--instance-ids', instance, '--document-name', 'AWS-RunShellScript',
                  '--parameters', json.dumps({'commands': [
                      'for i in $(seq 1 90); do [ -f /var/lib/xp25-relay/ready ] && break; sleep 10; done',
                      'cat /var/lib/xp25-relay/ready',
                      'sshd -T -C user=xp25tunnel,host=localhost,addr=127.0.0.1 | grep -Ei "^(listenaddress|allowtcpforwarding|gatewayports|permitlisten|permitopen|permittty|forcecommand|passwordauthentication) "',
                      'cat /etc/ssh/ssh_host_ed25519_key.pub']}))['Command']['CommandId']
    for _ in range(60):
        time.sleep(5)
        out = aws('ssm', 'get-command-invocation', '--command-id', command, '--instance-id', instance, check=False)
        if out and out['Status'] not in ('Pending', 'InProgress', 'Delayed'):
            break
    if out['Status'] != 'Success' or 'XP25_RELAY_READY' not in out['StandardOutputContent']:
        raise SystemExit('relay first boot failed:\n' + out['StandardOutputContent'] + out['StandardErrorContent'])
    lines = out['StandardOutputContent'].strip().splitlines()
    record['sshd_effective'] = [l for l in lines if l.split(' ')[0].lower() in (
        'listenaddress', 'allowtcpforwarding', 'gatewayports', 'permitlisten', 'permitopen', 'permittty', 'forcecommand', 'passwordauthentication')]
    host_key = ' '.join(lines[-1].split()[:2])
    if not host_key.startswith('ssh-ed25519 '):
        raise SystemExit('no host key returned')
    record['host_key'] = host_key
    step('host_key', host_key[:40] + '...')

    # 5. Home-host IAM user: SSH-over-SSM to this one instance, nothing else.
    policy = json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Sid': 'TunnelSession', 'Effect': 'Allow', 'Action': 'ssm:StartSession', 'Resource': [
            f'arn:aws:ec2:{a.region}:{account}:instance/{instance}',
            f'arn:aws:ssm:{a.region}::document/AWS-StartSSHSession'],
         'Condition': {'BoolIfExists': {'ssm:SessionDocumentAccessCheck': 'true'}}},
        {'Sid': 'OwnSessions', 'Effect': 'Allow', 'Action': ['ssm:TerminateSession', 'ssm:ResumeSession'],
         'Resource': f'arn:aws:ssm:{a.region}:{account}:session/${{aws:username}}-*'}]})
    if not aws('iam', 'get-user', '--user-name', a.user, check=False):
        aws('iam', 'create-user', '--user-name', a.user, '--tags', json.dumps(tags))
    aws('iam', 'put-user-policy', '--user-name', a.user, '--policy-name', 'xp25-tunnel-ssm', '--policy-document', policy)
    keys = aws('iam', 'list-access-keys', '--user-name', a.user)['AccessKeyMetadata']
    if not keys and a.access_key_out:
        k = aws('iam', 'create-access-key', '--user-name', a.user)['AccessKey']
        fd = os.open(a.access_key_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(f"[default]\naws_access_key_id = {k['AccessKeyId']}\naws_secret_access_key = {k['SecretAccessKey']}\n")
        step('access_key', 'created and written to --access-key-out')
    else:
        step('access_key', f'{len(keys)} existing key(s); none created')
    record.update(security_group=sg, vpc=vpc, subnet=a.subnet, iam_user=a.user, instance_profile=a.name)
    a.record.parent.mkdir(parents=True, exist_ok=True)
    a.record.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('instance_id', 'private_ip', 'security_group', 'iam_user')}))


if __name__ == '__main__':
    sys.exit(main())
