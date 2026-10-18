"""Load the Scare Floor scenario and apply deploy-time flag overrides.

Every consumer (the X-ray SCP, the WiFi inventory generator, the tests) imports
`load()` from here so they all agree on AE titles, the inmate, and the flags.

Flag overrides (so the committed repo never pins production flags):
    FLAG1_AE_TITLE  -> xray.called_aet_flag   (<= 16 bytes; it's an AE title)
    FLAG2_PRIVATE   -> inmate.private_tag_flag
Other optional overrides: SCENARIO_PATH, XRAY_PORT, XRAY_BIND.
"""
import os
import copy

try:
    import yaml
except ImportError as exc:  # pragma: no cover - surfaced clearly at runtime
    raise SystemExit("PyYAML is required: pip install pyyaml") from exc

_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenario.yaml")

# AE titles are capped at 16 bytes by the DICOM standard (VR 'AE').
AE_TITLE_MAX = 16


def load(path=None):
    """Return the scenario dict with flag/env overrides applied."""
    path = path or os.environ.get("SCENARIO_PATH", _DEFAULT_PATH)
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    data = copy.deepcopy(data)

    # --- Flag 1: the accepted called AE title -------------------------------
    flag1 = os.environ.get("FLAG1_AE_TITLE")
    if flag1:
        data["xray"]["called_aet_flag"] = flag1
    flag1 = data["xray"]["called_aet_flag"]
    if len(flag1.encode("ascii", "ignore")) > AE_TITLE_MAX:
        raise ValueError(
            f"Flag-1 AE title {flag1!r} is {len(flag1)} chars; DICOM caps AE "
            f"titles at {AE_TITLE_MAX} bytes. Pick a shorter secret."
        )
    # Keep the live AE title present in the published service pool so a
    # wordlist built from the inventory page can actually find it.
    pool = data["xray"].setdefault("service_aet_pool", [])
    if flag1 not in pool:
        pool.append(flag1)

    # --- Flag 2: the private-tag value --------------------------------------
    flag2 = os.environ.get("FLAG2_PRIVATE")
    if flag2:
        data["inmate"]["private_tag_flag"] = flag2

    # --- Networking knobs ---------------------------------------------------
    if os.environ.get("XRAY_PORT"):
        data["xray"]["listen_port"] = int(os.environ["XRAY_PORT"])

    return data


def patients(data):
    """Flatten the inmate + decoys into a uniform patient list for C-FIND.

    The known inmate carries `study` and `private_flag`; decoys do not.
    """
    out = []
    inmate = data["inmate"]
    out.append(
        {
            "PatientName": inmate["patient_name"],
            "PatientID": inmate["patient_id"],
            "PatientBirthDate": inmate.get("birth_date", ""),
            "PatientSex": inmate.get("sex", ""),
            "study": inmate.get("study"),
            "private_flag": inmate["private_tag_flag"],
        }
    )
    for d in data.get("decoy_patients", []):
        out.append(
            {
                "PatientName": d["patient_name"],
                "PatientID": d["patient_id"],
                "PatientBirthDate": d.get("birth_date", ""),
                "PatientSex": d.get("sex", ""),
                "study": None,
                "private_flag": None,
            }
        )
    return out


if __name__ == "__main__":
    import json

    cfg = load()
    print(json.dumps(cfg, indent=2))
