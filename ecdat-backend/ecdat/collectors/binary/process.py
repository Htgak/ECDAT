"""Bounded static-tool runner. Uploads are never used as executable commands."""
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

MAX_OUTPUT = 2 * 1024 * 1024


def run_tool(args: list[str], *, timeout: int, cwd: str):
    # JVM limits complement container memory/CPU limits. Do not use preexec_fn
    # in the threaded API worker (fork-time locks can deadlock).
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {'PATH', 'JAVA_HOME', 'HOME', 'USERPROFILE', 'SYSTEMROOT', 'TEMP', 'TMP', 'LANG'}}
    env['JAVA_TOOL_OPTIONS'] = '-Xmx768m -XX:ActiveProcessorCount=2'
    proc = subprocess.Popen(args, cwd=cwd, shell=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, start_new_session=os.name != 'nt')
    output = [bytearray(), bytearray()]
    overflow = threading.Event()

    def stop():
        if proc.poll() is None:
            try:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def drain(stream, buffer):
        try:
            while chunk := stream.read(65536):
                remaining = MAX_OUTPUT - len(buffer)
                buffer.extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    stop()
        finally:
            stream.close()

    threads = [threading.Thread(target=drain, args=(stream, buffer), daemon=True)
               for stream, buffer in zip((proc.stdout, proc.stderr), output)]
    for thread in threads:
        thread.start()
    try:
        deadline = time.monotonic() + timeout
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(args, timeout)
            total = 0
            for path in Path(cwd).rglob('*'):
                try:
                    if path.is_file() and not path.is_symlink():
                        total += path.stat().st_size
                except FileNotFoundError:
                    continue
                if total > 128 * 1024 * 1024:
                    stop()
                    raise ValueError('Static analysis output directory exceeded 128 MiB; analysis incomplete.')
            try:
                proc.wait(timeout=min(.2, max(.001, deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
    except subprocess.TimeoutExpired:
        stop()
        proc.wait(timeout=5)
        raise
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if overflow.is_set():
        raise ValueError('Static analysis tool exceeded the bounded output limit; analysis incomplete.')
    return subprocess.CompletedProcess(args, proc.returncode, bytes(output[0]), bytes(output[1]))
