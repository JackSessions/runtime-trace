# Contributing

Thanks for looking. This is a small project by one person, so the process is light.

1. Open an issue first for anything bigger than a bug fix.
2. `python3 -m unittest discover -s tests -v` must pass. The live-attach test needs root and `python3-bpfcc`; without them it is skipped, not required.
3. A new check needs a test that proves it fires on a fake "tampered" scenario and a test that proves a clean scenario stays quiet, the same bar PhantomTrace holds its checks to.
4. **False-positive reports are the most valuable contribution this project can get.** If a check fires on your clean, ordinary system, please open an issue with the exact finding: the module-hiding and LD_PRELOAD checks have both already been corrected once from real false positives found this way.
5. Nothing added to this project may help hide a process, a file, a module or any other artifact. RuntimeTrace detects anti-forensic and rootkit techniques; it does not implement them.

RuntimeTrace is MIT licensed.
