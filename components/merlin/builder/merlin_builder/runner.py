"""MerlinAI Builder job runner: the execution plane.

Takes queued jobs one at a time (max_concurrent_jobs, default 1), checks the
disk-space quota before each, and runs merlin_builder.pipeline. After an
interruption (the builder VM stopped or the runner was killed), jobs found in
an active state are marked failed with "interrupted" and their evidence is
kept; the user can request the build again. It never touches the API's
challenge state or credentials, and it holds no installation keys."""
import json
import shutil
import time

from .pipeline import Job
from .server import DEFAULT_LIMITS
from .store import ACTIVE, Store


def recover(store):
    for job, record in store.all_jobs():
        status = record['public'].get('status')
        if status in ACTIVE and status != 'queued':
            store.update(job, public={'status': 'failed', 'ready_to_apply': False,
                                      'stage': 'interrupted while %s; the evidence is kept, request the build again' % status,
                                      'not_ready_reason': 'the builder was interrupted'})


def next_job(store):
    queued = [(record['public']['created'], job) for job, record in store.all_jobs()
              if record['public'].get('status') == 'queued' and not record.get('cancel_requested')]
    return sorted(queued)[0][1] if queued else None


def enough_space(config):
    need = int(config.get('limits', {}).get('job_disk_reserve_gb', 15)) * (1 << 30)
    return shutil.disk_usage(config['data']).free >= need


def run(config, once=False):
    limits = dict(DEFAULT_LIMITS, **config.get('limits', {}))
    store = Store(config['data'], limits)
    recover(store)
    while True:
        job = next_job(store)
        if job and not enough_space(config):
            store.update(job, public={'stage': 'waiting: the builder is short of disk space'})
            job = None
        if job:
            Job(config, store, job).execute()
            continue
        if once:
            return 0
        time.sleep(5)


if __name__ == '__main__':
    import sys
    from pathlib import Path
    sys.exit(run(json.loads(Path(sys.argv[1]).read_text())))
