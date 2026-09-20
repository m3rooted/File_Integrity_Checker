# File Integrity Checker

Project URL: https://roadmap.sh/projects/file-integrity-checker

A small Python 3 command-line tool that detects changes to application log files with SHA-256 hashes. It uses only the Python standard library.

## Requirements and installation

Install Python 3. On Linux, clone this repository and run `chmod +x integrity-check` once. Run commands from the repository directory. No packages need to be installed.

## How it works

`init` reads each selected file in chunks and stores its SHA-256 hexadecimal digest as a trusted baseline. `check` calculates fresh digests and compares them with that baseline. `update` explicitly accepts a changed **file** as the new baseline. A directory command selects regular files directly inside that directory; it does not recurse into subdirectories. A directory baseline can be checked one file at a time.

The hashes persist at `$XDG_STATE_HOME/file-integrity-checker/hashes.json`, or `~/.local/state/file-integrity-checker/hashes.json` when `XDG_STATE_HOME` is unset. On Linux, the state directory is created with owner-only permissions and the file with mode `0600`. Keep this baseline outside directories that untrusted users can edit; anyone who can alter the baseline can defeat the check. Hashes detect changes but do not prove who made them.

## Usage

```bash
./integrity-check --help
./integrity-check init /var/log
Hashes stored successfully.

./integrity-check check /var/log/syslog
Status: Modified (Hash mismatch)

./integrity-check check /var/log/auth.log
Status: Unmodified

./integrity-check update /var/log/syslog
Hash updated successfully.
```

You can also pass a single file to `init`. A changed file or an error gives a nonzero exit status. Directory checks print each file path with its status. For a log directory containing files owned by other users, run with an account that can read those files and protect that account's state directory.

Run tests with `python3 -m unittest discover -s tests -v`.
