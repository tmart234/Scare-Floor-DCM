# Scare Floor — DICOM phase (stages 1–2)

> Part of the Biohacking Village CTF. Lead-in: **WiFi/network**. Lead-out: **HL7**.
> This phase: the prison hospital's radiology network.

## Briefing

You've pivoted off the guest WiFi into **Scare Floor Correctional's** clinical
VLAN. Somewhere on this segment is the ER's bedside X-ray unit — and the warden
has been very interested in one inmate's chest films.

From the WiFi stage you pulled the facility's **biomed asset registry** (the
DICOM device-inventory page). It lists each imaging device, the AE title it
connects with, and a pool of service AE titles the vendors use.

### Stage 1 — Get the X-ray to talk to you
The X-ray is picky about who it associates with. Figure out what AE title it
answers to. The AE title you recover is your first flag.

*Tools that fit: Wireshark, `nmap --script dicom-ping`, `nmap --script dicom-brute`.*

### Stage 2 — Pull inmate **SULLIVAN, JAMES** (#INM-11771)
Now that the X-ray trusts you, query it for Sullivan's record. Someone tagged
his study with a note they shouldn't have. That note is your second flag.

*Tools that fit: `findscu`, `pydicom`/`pynetdicom`.*

## What you're looking for
- **Flag 1:** the X-ray's accepted *called* AE title (a short secret string —
  submit it exactly as found; it is **not** wrapped in `BHV{...}`).
- **Flag 2:** a `BHV{...}` string hidden in a private DICOM tag on Sullivan's study.

## Connection
```
X-ray DICOM endpoint:  <your-team-target>:11112
```

## Hints
- A DICOM server can refuse you two ways: wrong *called* AE title, or an
  unrecognised *calling* AE title. The inventory page helps with both.
- `nmap`'s default calling AE title won't get you in. Whose identity can you
  borrow from the inventory?
- Private DICOM tags (odd group numbers) aren't in the standard dictionary, so
  your tools may show them as raw bytes. Decode them.
