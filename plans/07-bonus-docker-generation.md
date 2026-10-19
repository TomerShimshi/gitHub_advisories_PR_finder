# Plan 7: Bonus 2, Docker Compose generation for web apps

**Status:** Blocked on Plan 5
**Uses LLM:** Yes

## Goal
If an affected project is a web application with no Docker Compose setup, generate a Dockerfile and `compose.yml` that actually run it.

## Deliverable
- **Source download:** the only part of the project that needs files on disk. Tarball download or shallow clone of the affected version into a temp volume.
- **Detection:** is it a web app (Flask, Django, FastAPI, ...)? Does it already have a compose file? Deterministic checks first (dependency files, known entry points); LLM only when unclear.
- **Generation agent:** writes a Dockerfile and `compose.yml` from small, relevant context (dependency files, entry points, settings), not the whole repo.
- **Build and run loop:** build, start, health check over HTTP; on failure, give the error log back to the agent and retry, up to a fixed limit.
- **Isolation:** builds run in a separate `docker:dind` service that the tool reaches through `DOCKER_HOST`. The untrusted apps run inside that container, not on the host's Docker daemon. The host Docker socket is never mounted (that would give the container root-level control of the host).
- **Report:** generated files, attempts, and pass/fail added to the advisory's YAML entry.

## Definition of Done
- [ ] For at least 2 test repos with no compose file (e.g. one Flask app and one Django app), the generated setup builds, starts, and answers an HTTP request.
- [ ] Failures are reported with the last error, not hidden.
- [ ] Non-web projects and projects that already have a compose file are skipped with a reason.
- [ ] No container started by this plan runs on the host's Docker daemon.

## Security notes to leave in the code
- The dind service needs `privileged: true`. With more time: gVisor or Sysbox runtime, no network for builds after dependency install, CPU and memory limits.
- Generated Dockerfiles are untrusted: no host mounts, no extra privileges.

## Risks
- Real-world apps often need a database, secrets, or setup steps: the compose file may need extra services, and some apps will not start without manual config.
- Cost and time per app can be high: cap the retry count.

## Changes from earlier plans
_Update after Plan 5._

## Results
_Fill in when done._
