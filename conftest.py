import sage.all


def _patch_pytest_isolate_stderr_deadlock():
    """Fix an intermittent CLAASP test-suite hang caused by pytest-isolate.

    pytest-isolate runs each isolated test in a forked child whose stdout/stderr
    are redirected to two OS pipes. The parent drains those pipes while waiting
    for the child's result on a multiprocessing.Queue. In pytest_isolate 0.0.11
    the drain loop reads ``self.read_out`` twice and never reads
    ``self.read_err`` (copy/paste bug). Any isolated test whose child writes more
    than the 64 KiB pipe buffer to *raw* fd 2 (e.g. Gurobi/GLPK/SCIP/cryptominisat
    or sage/pexpect solver output) therefore blocks forever in ``write(2)`` while
    the parent blocks forever in ``q.get`` -> the xdist worker stalls and, under
    ``--dist loadfile``, the whole run hangs below 100%.

    This monkeypatch replaces run_in_subprocess with a corrected version that
    drains ``read_err`` too. It only activates when the exact buggy line is
    present, so it is a no-op on a fixed/updated plugin.
    """
    try:
        import inspect
        from pytest_isolate import plugin as _iso
    except Exception:
        return
    try:
        src = inspect.getsource(_iso.ForkedSubprocess.run_in_subprocess)
    except Exception:
        return
    if "err = self.read_out.read()" not in src:
        return  # not the known-buggy version; leave it alone

    import multiprocessing as mp
    import sys
    from queue import Empty

    dill = _iso.dill
    limits = _iso.limits
    allocate_resources = _iso.allocate_resources

    def run_in_subprocess(self, timeout, memlimit, cpulimit, resource_dict,
                          test_id, resource_timeout, target, args=()):
        ctx = mp.get_context("fork")
        q = ctx.Queue()
        timed_out = None

        def run_subprocess():
            self.child_redirect_streams()
            try:
                with limits(memlimit, cpulimit):
                    with allocate_resources(resource_dict, test_id, resource_timeout):
                        q.put(dill.dumps(target(*args)))
            except BaseException as e:
                q.put(dill.dumps(e))
            sys.stdout.flush()
            sys.stderr.flush()

        p = ctx.Process(target=run_subprocess)
        p.start()
        self.parent_open_streams()
        delta = self.wait_delta
        time_left = timeout or delta
        result = None

        def _drain():
            if not self.streams_ready:
                return
            out = self.read_out.read()
            if out:
                print(out.decode(errors="replace"), file=sys.stdout)
            err = self.read_err.read()  # FIX: upstream reads read_out here
            if err:
                print(err.decode(errors="replace"), file=sys.stderr)

        while time_left > 0:
            try:
                result = dill.loads(q.get(block=True, timeout=min(delta, time_left)))
            except Empty:
                if not p.is_alive():
                    break
                if timeout is not None:
                    time_left = time_left - delta
            except Exception as e:
                result = e
                break
            finally:
                _drain()
        sys.stdout.flush()
        sys.stderr.flush()
        if time_left <= 0:
            timed_out = timeout
        if p.is_alive() and (time_left <= 0):
            p.kill()
        p.join()
        _drain()  # final flush of anything left in the pipes
        return p.exitcode, timed_out, result

    _iso.ForkedSubprocess.run_in_subprocess = run_in_subprocess


_patch_pytest_isolate_stderr_deadlock()


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
