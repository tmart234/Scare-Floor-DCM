#!/usr/bin/env python3
"""Generate the WiFi-stage "DICOM Device Inventory" page from the scenario.

This page belongs to the lead-in (WiFi) stage, but it is generated here, from
the same shared/scenario.yaml the X-ray SCP uses, so the AE titles a player
harvests on the WiFi stage are guaranteed to match what the X-ray enforces.

What it leaks (by design):
  * each device's CALLING AE title  -> the player needs one of these as
    dicom.calling_aet for nmap dicom-brute to get past calling-AET enforcement
  * a pool of service/console AE titles -> the brute-force wordlist for the
    CALLED AE title. The live one (flag 1) sits in this pool unmarked, among
    decoys, so the page alone doesn't give it away.

Usage:
    python inventory/gen_inventory.py            # -> inventory/device-inventory.html
    python inventory/gen_inventory.py --wordlist # -> prints just the AET wordlist
"""
import os
import sys
import html
import random
import argparse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "shared"))
import scenario  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device-inventory.html")

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Biomed Asset Registry &mdash; Scare Floor Correctional</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
         margin: 0; background: #0f1419; color: #c9d1d9; }}
  header {{ background: #161b22; padding: 18px 24px; border-bottom: 2px solid #f85149; }}
  header h1 {{ margin: 0; font-size: 18px; color: #f0f6fc; }}
  header p {{ margin: 4px 0 0; font-size: 12px; color: #8b949e; }}
  main {{ padding: 24px; max-width: 980px; }}
  h2 {{ font-size: 14px; color: #f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0 28px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #21262d; }}
  th {{ color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }}
  td.aet {{ color: #7ee787; }}
  .note {{ font-size: 12px; color: #8b949e; background: #161b22; padding: 10px 14px;
          border-left: 3px solid #d29922; margin: 12px 0; }}
  footer {{ padding: 16px 24px; font-size: 11px; color: #484f58; border-top: 1px solid #21262d; }}
</style>
</head>
<body>
<header>
  <h1>Biomed Asset Registry</h1>
  <p>{facility} &middot; internal use only &middot; DICOM connectivity sheet</p>
</header>
<main>
  <div class="note">
    Auto-exported from the modality connection manager. Lists every imaging
    device's DICOM identity (Application Entity title) and its archive route.
    Keep current when swapping field-service hardware.
  </div>

  <h2>Imaging devices (Application Entities)</h2>
  <table>
    <tr><th>Device</th><th>Host</th><th>AE Title (calling)</th><th>Role</th><th>DICOM Port</th></tr>
    {device_rows}
  </table>

  <h2>Standard service / console AE titles</h2>
  <div class="note">
    Field-service and vendor consoles connect using one of the following
    "called" AE titles depending on firmware generation. If a modality rejects
    an association, try the next title on this list.
  </div>
  <table>
    <tr><th>#</th><th>Called AE Title</th></tr>
    {service_rows}
  </table>
</main>
<footer>Scare Floor Correctional Medical &mdash; Biomedical Engineering &mdash; do not distribute</footer>
</body>
</html>
"""


def render(cfg):
    facility = html.escape(cfg["facility"]["name"])
    port = cfg["xray"]["listen_port"]

    device_rows = "\n    ".join(
        "<tr><td>{name}</td><td>{host}</td><td class='aet'>{aet}</td>"
        "<td>{role}</td><td>{port}</td></tr>".format(
            name=html.escape(d["name"]),
            host=html.escape(d["host"]),
            aet=html.escape(d["calling_aet"]),
            role=html.escape(d["role"]),
            port=port if d["role"] == "modality" else "&mdash;",
        )
        for d in cfg["devices"]
    )

    # Shuffle the pool so the live AET (flag 1) isn't always in the same slot.
    pool = list(cfg["xray"]["service_aet_pool"])
    random.Random(cfg["xray"]["called_aet_flag"]).shuffle(pool)
    service_rows = "\n    ".join(
        "<tr><td>{i}</td><td class='aet'>{aet}</td></tr>".format(
            i=i + 1, aet=html.escape(a)
        )
        for i, a in enumerate(pool)
    )

    return PAGE.format(
        facility=facility, device_rows=device_rows, service_rows=service_rows
    )


def wordlist(cfg):
    """The AET wordlist a player would lift off the page for dicom-brute."""
    pool = list(cfg["xray"]["service_aet_pool"])
    random.Random(cfg["xray"]["called_aet_flag"]).shuffle(pool)
    return pool


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", action="store_true",
                    help="print the called-AE-title wordlist and exit")
    args = ap.parse_args()
    cfg = scenario.load()

    if args.wordlist:
        print("\n".join(wordlist(cfg)))
        return

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(render(cfg))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
