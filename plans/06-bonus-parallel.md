# Plan 6: Bonus 1, parallel agents across advisories

**Status:** Blocked on Plan 5
**Uses LLM:** Yes

## Goal
Process many advisories at once, faster, with the same results and no extra cost.

## Deliverable
- **Concurrency:** run the per-advisory graph concurrently (asyncio with a semaphore, or LangGraph's fan-out), with a configurable worker count.
- **Shared GitHub rate limiter:** reads the rate-limit headers, slows down before hitting the limit, backs off on secondary limits.
- **Shared budget guard:** one global budget across workers; when it is reached, running advisories finish their current step and no new ones start.
- **Thread-safe cache and cost accounting.**

## Definition of Done
- [ ] On the same set of N advisories, the parallel run is clearly faster than the sequential one (times recorded in **Results**).
- [ ] Parallel and sequential reports have the same results.
- [ ] No rate-limit failures in the logs.
- [ ] With a low budget cap, total spend never goes over it by more than the cost of the calls already in flight.

## Risks
- GitHub secondary rate limits punish bursts of concurrent requests: keep the default worker count small.

## Changes from earlier plans
_Update after Plan 5._

## Results
_Fill in when done._
