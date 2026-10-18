#!/usr/bin/env python3
"""End-to-end tests for Scare Floor DCM stages 1 & 2.

Starts the real X-ray SCP on a loopback port, then drives it with a pynetdicom
SCU to prove:

  Stage 1 (AE enforcement):
    * correct calling + called AE title  -> association ACCEPTED (C-ECHO ok)
    * wrong called AE title              -> association REJECTED
    * wrong (unknown) calling AE title   -> association REJECTED

  Stage 2 (C-FIND private tag):
    * C-FIND for the known inmate returns the private-tag flag
    * C-FIND for a decoy patient does NOT leak the flag

Run:  python tests/test_xray_stages.py
Exit code 0 = all pass.
"""
import os
import sys
import time
import threading

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "shared"))
sys.path.insert(0, os.path.join(REPO, "challenge", "xray-scp"))

import scenario  # noqa: E402

from pydicom.dataset import Dataset  # noqa: E402
from pynetdicom import AE  # noqa: E402
from pynetdicom.sop_class import (  # noqa: E402
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
)

TEST_PORT = int(os.environ.get("TEST_PORT", "11199"))
HOST = "127.0.0.1"

CFG = scenario.load()
FLAG1 = CFG["xray"]["called_aet_flag"]          # accepted called AE title
FLAG2 = CFG["inmate"]["private_tag_flag"]       # private-tag value
GOOD_CALLING = CFG["xray"]["require_calling_aet"][0]   # e.g. XRAY_ER_01
INMATE = CFG["inmate"]["patient_name"]

PASS, FAIL = "✅", "❌"
_results = []


def check(name, condition):
    _results.append(condition)
    print(f"{PASS if condition else FAIL} {name}")


def _find_flag(ds):
    """Scan a returned dataset for the BHV flag the way a solver would.

    A private tag with no local dictionary comes back as VR UN with raw,
    space/null-padded bytes, so check both str and decoded-bytes values.
    """
    for elem in ds:
        val = elem.value
        if isinstance(val, bytes):
            try:
                val = val.decode("ascii")
            except UnicodeDecodeError:
                continue
        if isinstance(val, str) and "BHV{" in val:
            return val.strip().strip("\x00").strip()
    return None


def start_server():
    os.environ["XRAY_PORT"] = str(TEST_PORT)
    os.environ["XRAY_BIND"] = HOST
    import xray_scp  # imported after env set

    # Reload scenario/port into the module's globals.
    xray_scp.SCENARIO = scenario.load()
    xray_scp.PATIENTS = scenario.patients(xray_scp.SCENARIO)
    ae = xray_scp.build_ae()
    handlers = [
        (__import__("pynetdicom").evt.EVT_C_ECHO, xray_scp.handle_echo),
        (__import__("pynetdicom").evt.EVT_C_FIND, xray_scp.handle_find),
    ]
    server = ae.start_server((HOST, TEST_PORT), block=False, evt_handlers=handlers)
    return server


def associate(calling_aet, called_aet, context=Verification):
    ae = AE(ae_title=calling_aet)
    ae.add_requested_context(context)
    return ae.associate(HOST, TEST_PORT, ae_title=called_aet)


def test_stage1():
    print("\n-- Stage 1: AE-title enforcement --")

    assoc = associate(GOOD_CALLING, FLAG1)
    check("correct calling + called AE -> ACCEPTED", assoc.is_established)
    if assoc.is_established:
        status = assoc.send_c_echo()
        check("C-ECHO succeeds on valid association",
              status and status.Status == 0x0000)
        assoc.release()

    assoc = associate(GOOD_CALLING, "WRONG_AET")
    check("wrong called AE title -> REJECTED", not assoc.is_established)
    if assoc.is_established:
        assoc.release()

    assoc = associate("EVIL_LAPTOP", FLAG1)
    check("unknown calling AE title -> REJECTED", not assoc.is_established)
    if assoc.is_established:
        assoc.release()


def test_stage2():
    print("\n-- Stage 2: C-FIND private-tag flag --")

    assoc = associate(GOOD_CALLING, FLAG1,
                      context=PatientRootQueryRetrieveInformationModelFind)
    if not assoc.is_established:
        check("association for C-FIND established", False)
        return

    def query(patient_name):
        ds = Dataset()
        ds.QueryRetrieveLevel = "PATIENT"
        ds.PatientName = patient_name
        ds.PatientID = ""
        found = []
        for status, identifier in assoc.send_c_find(
            ds, PatientRootQueryRetrieveInformationModelFind
        ):
            if status and status.Status in (0xFF00, 0xFF01) and identifier:
                found.append(identifier)
        return found

    inmate_matches = query(INMATE)
    got_flag = any(_find_flag(ds) == FLAG2 for ds in inmate_matches)
    check(f"C-FIND {INMATE} returns private-tag flag", got_flag)

    decoy = CFG["decoy_patients"][0]["patient_name"]
    decoy_matches = query(decoy)
    decoy_leaks = any(_find_flag(ds) for ds in decoy_matches)
    check(f"decoy {decoy} does NOT leak the flag",
          len(decoy_matches) >= 1 and not decoy_leaks)

    assoc.release()


def main():
    print(f"Flag1 (AE title): {FLAG1!r}   Flag2: {FLAG2!r}")
    server = start_server()
    time.sleep(1.0)
    try:
        test_stage1()
        test_stage2()
    finally:
        server.shutdown()

    print()
    if all(_results):
        print(f"{PASS} all {len(_results)} checks passed")
        return 0
    print(f"{FAIL} {_results.count(False)}/{len(_results)} checks FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
