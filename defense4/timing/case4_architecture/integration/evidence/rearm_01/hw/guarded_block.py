#!/usr/bin/env python3
"""Shared no-clobber entrypoint for the ordinary and frozen block wrappers."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile


HW = Path(__file__).resolve().parent
ARCH = HW.parents[3]


def existing(path):
    # A dangling symlink is retained evidence too.
    return os.path.lexists(str(path))


def refuse_retained(root, record, run_id):
    paths = [root, record, Path(tempfile.gettempdir()) / ('run_block_%s.out' % run_id),
             Path(tempfile.gettempdir()) / ('run_block_%s.out.plan' % run_id)]
    for path in paths:
        if existing(path):
            raise ValueError('retained run path already exists: %s; use a new run ID' % path)


def copy_new(source, destination):
    with open(source, 'rb') as src, open(destination, 'xb') as dst:
        shutil.copyfileobj(src, dst)


def command_output(command, output, env=None):
    with open(output, 'xb') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            return process.wait()
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise


def log_event(message):
    with open(HW / 'run_block.log', 'a') as log:
        log.write('%s %s\n' % (datetime.now().astimezone().isoformat(), message))


def block(tool, config, run_id, arguments, freeze=None):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', run_id):
        raise ValueError('run ID must be one ordinary path component')
    if not re.fullmatch(r'candidate_[a-z_]+', tool) or not (HW / (tool + '.py')).is_file():
        raise ValueError('unknown candidate block tool: ' + tool)
    # Reserved options cannot redirect the command away from the root checked here.
    if any(arg.startswith('--') and any(option.startswith(arg.split('=', 1)[0])
                                        for option in ('--config', '--run-id', '--apply'))
           for arg in arguments):
        raise ValueError('wrapper owns --config, --run-id and --apply')
    config = Path(config).resolve(strict=True)
    if freeze is not None:
        freeze = str(Path(freeze).resolve())
    cfg = json.loads(config.read_text())
    os.chdir(ARCH.parents[2])
    supplied_root = ARCH / cfg['evidence_dir'] / run_id
    if existing(supplied_root):
        raise ValueError('retained run path already exists: %s; use a new run ID' % supplied_root)
    root = supplied_root.resolve()
    record = HW / 'freeze_checks' / (run_id + '.json')
    refuse_retained(root, record, run_id)
    # Reserve both identities outside root: Campaign requires root to be absent.
    reservations = HW / 'run_reservations'
    reservations.mkdir(exist_ok=True)
    names = ['id_' + run_id, 'root_' + hashlib.sha256(str(root).encode()).hexdigest()]
    owned = []
    try:
        for name in names:
            reservation = reservations / name
            reservation.mkdir()  # exclusive across both wrappers and config aliases
            owned.append(reservation)
        refuse_retained(root, record, run_id)
        with tempfile.TemporaryDirectory(prefix='run_block_%s_' % run_id) as temp:
            temp = Path(temp)
            freeze_record = temp / 'freeze_check.json'
            if freeze is not None:
                rc = subprocess.run([sys.executable, str(HW / 'freeze_gate.py'), 'check', freeze,
                                     '--config', str(config), '--record', str(freeze_record)]).returncode
                if rc:
                    return 3
            command = [sys.executable, str(HW / (tool + '.py'))]
            options = ['--config', str(config), '--run-id', run_id] + arguments
            plan = temp / 'plan.out'
            rc = command_output(command + ['plan'] + [a for a in options if a != '--dry-run'], plan)
            text = plan.read_text(errors='replace')
            if rc or 'BLOCKED/UNBOUND (a real run refuses):' in text:
                sys.stderr.write(text)
                return 1
            if '--dry-run' in arguments:
                sys.stdout.write(text)
                return 0
            # Recheck immediately before entry; preflight refusal never calls restore.
            refuse_retained(root, record, run_id)
            if freeze is not None:
                record.parent.mkdir(exist_ok=True)
                copy_new(freeze_record, record)
            log_event('START %s %s' % (tool, run_id))
            run = temp / 'run.out'
            env = dict(os.environ, DEFENSE4_HW_AUTHORIZED='1')
            try:
                rc = command_output(command + ['run', '--apply'] + options, run, env)
            except (Exception, KeyboardInterrupt) as error:
                rc = 1
                # A wait/logging error may occur after the child entered hardware.
                # Decide entry from Campaign's root before handling the failure.
                if isinstance(error, KeyboardInterrupt):
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                sys.stderr.write('block command failed; checking for hardware entry: %s\n' % error)
                try:
                    with open(run, 'a') as log:
                        log.write('\nblock command failed; verifying restoration: %s\n' % error)
                except OSError:
                    pass
            if not root.is_dir():
                # Campaign creates root before deploy. No root means no hardware entry.
                sys.stderr.write(run.read_text(errors='replace'))
                log_event('REFUSED %s block_rc=%s (no hardware entry)' % (run_id, rc))
                return 1
            restore = temp / 'restore.out'
            # Run this independently even when the block failed. Keep its output in
            # our temporary directory until the checker has completed.
            try:
                rv = command_output([sys.executable, str(HW / 'restore_verify.py'), '--config', str(config),
                                     '--run-root', str(root)], restore)
            except (Exception, KeyboardInterrupt) as error:
                rv = 1
                sys.stderr.write('post-entry restoration could not be verified: %s\n' % error)
                try:
                    with open(restore, 'a') as log:
                        log.write('restoration could not be verified: %s\n' % error)
                except OSError:
                    pass
            try:
                copy_new(plan, root / 'run_block_plan.out')
                copy_new(run, root / 'run_block_run.out')
                copy_new(restore, root / 'restore_verify.out')
                if freeze is not None:
                    copy_new(freeze_record, root / 'freeze_check.json')
            except (OSError, KeyboardInterrupt) as error:
                sys.stderr.write('could not retain wrapper evidence: %s\n' % error)
                return 2
            try:
                log_event('END %s block_rc=%s restore_verify_rc=%s' % (run_id, rc, rv))
            except (OSError, KeyboardInterrupt) as error:
                sys.stderr.write('post-entry log failed (restore_verify_rc=%s): %s\n' % (rv, error))
                return 2 if rv else 1
            return 2 if rv else (1 if rc else 0)
    finally:
        for reservation in reversed(owned):
            try:
                reservation.rmdir()
            except (OSError, KeyboardInterrupt) as error:
                # Cleanup must never downgrade an unverified-restoration stop.
                sys.stderr.write('reservation cleanup failed: %s\n' % error)


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze')
    parser.add_argument('tool')
    parser.add_argument('config')
    parser.add_argument('run_id')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        return block(args.tool, args.config, args.run_id, args.arguments, args.freeze)
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt) as error:
        sys.stderr.write('REFUSED (nothing entered): %s\n' % error)
        return 1


if __name__ == '__main__':
    sys.exit(main())
