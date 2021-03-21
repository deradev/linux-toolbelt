# linux-toolbelt
Linux tools for development and system analysis.

lsmaps.py - List all shared libraries mapped in memory.
            Read-out and parse /proc/[pid]/maps entries (https://man7.org/linux/man-pages/man5/proc.5.html).
            Included maps must allow PTRACE_MODE_READ_FSCREDS and PTRACE_MODE_NOAUDIT ptrace access mode for calling user.
