# Releasing to PyPI

One-time setup (about 5 minutes):

1. Push `main` to `github.com/JackSessions/runtime-trace`.
2. On https://pypi.org, log in, then Your account > Publishing > Add a new pending publisher. Type these by hand rather than pasting, so no hidden character sneaks in:
   - PyPI project name: `runtime-trace`
   - Owner: `JackSessions`
   - Repository name: `runtime-trace`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. On GitHub: Settings > Environments > New environment, name it `pypi` (optionally require your approval before each publish).

Each release:

1. Update the version in `pyproject.toml` and `runtime_trace/__init__.py`, and `CITATION.cff`, and add a section to `CHANGELOG.md`.
2. `python -m unittest discover -s tests` and, as root, `sudo python3 -m unittest discover -s "$(pwd)/tests" -v -p test_collector.py` (proves the live eBPF collector still attaches).
3. `python -m build && python -m twine check dist/*`.
4. Commit, push, then create a GitHub Release with the tag `vX.Y.Z` (the tag must match the version). Publishing the release runs `.github/workflows/publish.yml`: it builds, checks, and publishes to PyPI with trusted publishing (no token stored).
5. Check https://pypi.org/project/runtime-trace/ and try `pipx install --system-site-packages runtime-trace` on a clean machine with `python3-bpfcc` installed.

A version number can only be uploaded once, even if you delete the release, so run the checks above first.
