"""
Which engine the tests run on (simulator.default_engine(): ALISIM_ENGINE, set
by run_all_tests.py --engine), for the tests and scenarios that check one
engine's own machinery.  The Unicorn engine works around Unicorn with CP0
instruction sites, a slice stopper, replayed device accesses, a forced ERL or
a wired TLB entry, an hflags calibration; the C++ core has none of those
problems, so those checks do not apply to it (its own behaviour is checked
by the same tests' other scenarios and by tools/cpp_lockstep.py,
cpp_bisect.py and cpp_fuzz.py against Unicorn).
"""
import sys

import simulator

ENGINE = simulator.default_engine()
CPP = ENGINE == "cpp"


def not_applicable(why):
    """The whole test checks machinery this engine does not have: say so (the
    runner counts it apart from the passes) and end the test."""
    print(f"[NOT APPLICABLE] on the {ENGINE} engine: {why}")
    sys.exit(0)


def unicorn_only(why):
    """A scenario that checks the Unicorn engine's machinery: True to run it,
    else a note that it does not apply and False."""
    if CPP:
        print(f"  (not applicable on the C++ engine: {why})")
        return False
    return True
