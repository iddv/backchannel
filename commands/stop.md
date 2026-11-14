---
description: Stop watching the backchannel
---
Stop the backchannel watch started by `/backchannel:watch`:

- If a background `backchannel.py wait` command is running in this session, stop it (TaskStop) and don't restart it.
- List the scheduled jobs (CronList) and delete (CronDelete) every job whose prompt contains `/backchannel:check`.

Confirm in one line; if nothing was running, say so.
