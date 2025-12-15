from pathlib import Path

import os
import pty
import time
import signal
import resource

def main():
    coal_path = Path("./coal").resolve()
    assert not coal_path.exists()
    assert Path.home() in coal_path.parents

    challenge_path = Path("/challenge/claus")
    assert challenge_path.exists()

    pid, master_fd = pty.fork()
    if pid == 0:
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        argv = [challenge_path.as_posix()]
        os.execv(argv[0], argv)
        assert False, "Unreachable"
    else:
        print(f"child pid: {pid}, master_fd: {master_fd}", pid)

        # Give the child a moment to initialize
        time.sleep(1)
        print("sending SIGQUIT...")
        os.write(master_fd, b'\x1c')
        _, status = os.waitpid(pid, 0)

        assert os.WIFSIGNALED(status)
        assert os.WTERMSIG(status) == signal.SIGQUIT

        assert coal_path.exists()
        
        os.close(master_fd)
        print(f"Coal dumped in {coal_path}, please restart in practice mode to open it")

if __name__ == "__main__":
    main()
