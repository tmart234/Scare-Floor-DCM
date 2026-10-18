# Scare Floor DCM — Biohacking Village CTF (DICOM phase)

A DICOM medical-imaging CTF stage themed around a **prison hospital**
("Scare Floor Correctional"). It is one phase of a larger village CTF:

```
[ WiFi / network ]  →  DICOM PHASE (this repo)  →  [ HL7 / ORM ]
                         X-ray → c-arm → PACS → modality worklist
```

This repo currently implements the **first two stages** of the DICOM phase,
both on a single endpoint: the ER Portable X-ray modality.

| Stage | Goal | Flag | Tooling |
|------|------|------|---------|
| **1** | Discover the X-ray's accepted AE title | the AE title itself (≤16-char secret, submitted verbatim) | Wireshark, `nmap --script dicom-ping` / `dicom-brute` |
| **2** | C-FIND a known inmate; read a private tag | `BHV{...}` | `findscu`, `pynetdicom` |

### The chain
1. The **WiFi stage** leaks a *device-inventory page* (`inventory/`) listing each
   device's calling AE title plus a pool of service AE titles.
2. **Stage 1:** the X-ray enforces both *called* and *calling* AE titles. nmap's
   default calling AE title is rejected, so the player must reuse a leaked device
   AE title (e.g. `XRAY_ER_01`) and brute-force the *called* AE title from the
   service pool. The accepted called AE title **is flag 1**.
3. **Stage 2:** with a valid association, a C-FIND for inmate **SULLIVAN^JAMES**
   returns a private tag `(0009,"SCARE_FLOOR_DCM",01)` holding **flag 2**.
4. **Lead-out:** a Modality Worklist C-FIND exposes the scheduled order
   (`AccessionNumber=ACC-SCARE-0001`, `PlacerOrderNumber=ORD-7742`) — the key the
   HL7/ORM stage replays.

## Layout
```
shared/scenario.yaml        Single source of truth: devices, AE titles, inmate,
                            worklist order, and (default) flags. Everything else
                            derives from this so all stages line up.
shared/scenario.py          Loader with deploy-time flag/env overrides.

challenge/xray-scp/         The X-ray modality SCP (pynetdicom) — stages 1 & 2.
  xray_scp.py               AE enforcement + C-ECHO + C-FIND (+ MWL scaffold).
  Dockerfile, requirements.txt

inventory/gen_inventory.py  Generates the WiFi-stage device-inventory page +
                            the brute-force AE wordlist from scenario.yaml.

deploy/k8s/                 Per-team Kubernetes manifests (LoadBalancer/NodePort
                            exposing raw DICOM TCP), flag Secret template.
deploy/docker-compose.yml   Local dev smoke test.
deploy/README.md            Build + per-team deploy + networking notes.

solution/                   Stage 1 & 2 walkthroughs + reference solver.
tests/test_xray_stages.py   End-to-end AE-enforcement + C-FIND flag tests.
```

## Quick start
```bash
# deps
pip install -r challenge/xray-scp/requirements.txt

# run the X-ray locally
python challenge/xray-scp/xray_scp.py            # listens on :11112

# in another shell — prove it works
nmap -p 11112 --script dicom-ping 127.0.0.1
python tests/test_xray_stages.py                 # 6/6 checks
```
See `deploy/README.md` for Docker/Kubernetes, and `solution/` for full solves.

## Flags
- **Flag 1** (stage 1): the accepted called AE title, e.g. `BHV_XR_9F2C71A4`
  (a short secret, not `BHV{...}` — AE titles are capped at 16 bytes).
- **Flag 2** (stage 2): `BHV{...}` in a private DICOM tag.

Flags are injected at deploy time via a Kubernetes Secret
(`deploy/k8s/flags.secret.example.yaml`); the committed defaults are examples
only. Rotate per event — see `deploy/README.md`.

## Status / roadmap
- ✅ Stage 1 — AE-title enforcement + brute force (verified with nmap).
- ✅ Stage 2 — C-FIND private-tag flag (verified with findscu & pynetdicom).
- 🔜 c-arm C-STORE → Orthanc PACS (scaffolded: `deploy/k8s/orthanc-pacs.yaml`).
- 🔜 Modality Worklist → HL7/ORM handoff (worklist responder already live).

> **Legacy:** `challenge/dcmtk/`, `challenge/orthanc/`, `packer/`, and
> `solution/{scapy_DICOM.py,fuzzer,cve_datasets.py}` are from the previous
> "MedImage Crisis" design and are **not** part of stages 1–2. They're kept for
> possible reuse in later stages; ignore them when working on this phase.

---
This is authorized Biohacking Village CTF content. The deliberate
"misconfigurations" (AE-title trust, private-tag over-sharing on C-FIND) are the
intended teaching points about medical-imaging network security.
