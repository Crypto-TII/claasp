import sage.all


def _install_isolate_timeout_retry():
    """Auto-retry an isolated test that was killed by --isolate-timeout.

    A rare, fundamental issue: pytest-isolate fork()s each test off the
    multithreaded xdist worker, and Sage's Singular allocator (omalloc, mapped
    in every worker) is not fork-safe. Very occasionally a forked child
    deadlocks on an inherited lock (seen ~1 run in 24, in the algebraic tests).
    --isolate-timeout turns that infinite hang into a killed+failed test; this
    wrapper then re-forks the test up to ISOLATE_RETRIES times. A fresh fork
    almost never hits the same race, so the test passes on retry and the run
    stays green instead of showing a spurious timeout failure.

    Implemented by wrapping plugin.run_in_subprocess (which pytest_runtest_protocol
    calls by module-global name), so only the final attempt's reports are logged
    -- no duplicate reports, and no dependency on pytest-rerunfailures (which
    cannot compose with pytest-isolate: both own pytest_runtest_protocol).
    """
    import os
    try:
        from pytest_isolate import plugin as _iso
    except Exception:
        return
    if getattr(_iso, "_claasp_retry_installed", False):
        return

    try:
        retries = int(os.environ.get("ISOLATE_RETRIES", "2"))
    except ValueError:
        retries = 2
    if retries < 1:
        return

    _orig_run_in_subprocess = _iso.run_in_subprocess

    def _is_timeout_failure(reports):
        # pytest-isolate's timeout report is built with when='???' (not 'call')
        # and longrepr 'Timeout > N'; match on the outcome + marker text only.
        for rep in reports or ():
            if (getattr(rep, "outcome", None) == "failed"
                    and "Timeout >" in str(getattr(rep, "longrepr", ""))):
                return True
        return False

    def run_in_subprocess_with_retry(item, timeout, mem_limit, cpu_limit, wait_delta):
        reports = _orig_run_in_subprocess(item, timeout, mem_limit, cpu_limit, wait_delta)
        attempt = 0
        while attempt < retries and _is_timeout_failure(reports):
            attempt += 1
            try:
                os.write(2, ("[isolate-retry] %s timed out (>%ss); retry %d/%d\n"
                             % (item.nodeid, timeout, attempt, retries)).encode())
            except Exception:
                pass
            reports = _orig_run_in_subprocess(item, timeout, mem_limit, cpu_limit, wait_delta)
        return reports

    _iso.run_in_subprocess = run_in_subprocess_with_retry
    _iso._claasp_retry_installed = True


_install_isolate_timeout_retry()
