# File Integrity Checker threat model

## Scope and assumptions

This local Python CLI reads user-selected log files and keeps a JSON SHA-256 baseline in the invoking user's state directory. It has no network service or authentication. The intended operator can read monitored files and owns the state directory. A separate user may be able to alter application logs but should not be able to write the operator's baseline.

## Assets, boundaries, and abuse paths

| Asset / boundary | Abuse path | Impact | Control |
| :--- | :--- | :--- | :--- |
| Log files | Modify or delete a file | Change goes unnoticed | Hash and missing-file checks |
| Trusted baseline | Replace stored hashes | Tampering looks valid | Private state directory |
| CLI input path | Select the wrong file | Wrong file is monitored | Resolved absolute paths |

The log-file check compares SHA-256 values. When checking a directory, it also reports monitored files that are missing.

The baseline is stored in the operator's state directory. On POSIX systems, the program checks ownership, permissions, and symbolic links, then writes the baseline atomically with mode `0600`. The operator must keep this directory private.

The CLI stores resolved absolute paths so each hash stays associated with its file. Operators should verify the path before running `init`.

The main remaining limitation is that a user who controls both the log files and the operator's baseline, or who can run `update` as the operator, can accept tampered content. SHA-256 detects differences from a protected baseline; it does not authenticate the author of a change. Priority is medium if logs are writable by another account while the state directory remains private, and high if the baseline is shared or writable by that account.
