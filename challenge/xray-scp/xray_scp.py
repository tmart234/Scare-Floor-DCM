#!/usr/bin/env python3
"""Scare Floor DCM - ER Portable X-ray modality (challenge stages 1 & 2).

A deliberately-configured DICOM Service Class Provider that models a prison
hospital's bedside X-ray. It is the single network endpoint for the first two
stages of the DICOM phase:

  Stage 1 (Flag 1): AE-title enforcement.
    * Only ONE called AE title is accepted; every other association is
      rejected with A-ASSOCIATE-RJ (visible in Wireshark / detectable with
      `nmap --script dicom-ping`).
    * The calling AE title must be a known device from the fleet (the player
      harvests one from the WiFi stage's device-inventory page).
    * Discovering the accepted called AE title with `nmap --script dicom-brute`
      (seeded from the inventory's service-AET pool) IS flag 1. AE titles are
      <= 16 bytes, so the flag is that short secret string itself.

  Stage 2 (Flag 2): C-FIND a known inmate.
    * With a valid association, a Patient/Study-root C-FIND for inmate
      SULLIVAN^JAMES returns a response carrying a private tag
      (0009,"SCARE_FLOOR_DCM",01) whose value is flag 2 (BHV{...}).

  Lead-out scaffold: a Modality Worklist C-FIND returns a scheduled order
  whose AccessionNumber + PlacerOrderNumber are the handoff key the HL7/ORM
  stage replays.

This is authorized Biohacking Village CTF content; the "misconfiguration" is
the intended lesson about AE-title trust and over-sharing on C-FIND.
"""
import logging
import os
import re
import sys

# Make the shared scenario loader importable whether we run from the repo
# (shared/ at repo root) or from the container (shared/ copied next to this
# file by the Dockerfile).
_HERE = os.path.dirname(os.path.abspath(__file__))
for _cand in (
    os.path.join(_HERE, "shared"),            # container: /app/shared
    os.path.join(_HERE, "..", "..", "shared"),  # repo: <root>/shared
    _HERE,
):
    if os.path.isdir(_cand):
        sys.path.insert(0, os.path.abspath(_cand))

import scenario  # noqa: E402  (path set above)

from pydicom.dataset import Dataset  # noqa: E402
from pynetdicom import AE, evt  # noqa: E402
from pynetdicom.sop_class import (  # noqa: E402
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelFind,
    ModalityWorklistInformationFind,
)

PRIVATE_CREATOR = "SCARE_FLOOR_DCM"
PRIVATE_GROUP = 0x0009
PRIVATE_ELEMENT = 0x01  # -> (0009,1001) once the creator block is reserved

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [xray-scp] %(levelname)s %(message)s",
)
log = logging.getLogger("xray-scp")


# ---------------------------------------------------------------------------
# Matching helpers (DICOM C-FIND wildcard semantics, kept intentionally simple)
# ---------------------------------------------------------------------------
def _matches(query_value, actual_value):
    """True if a C-FIND query key matches. Empty or '*' is universal match."""
    if query_value in (None, "", "*"):
        return True
    # DICOM wildcards: '*' = any run, '?' = any single char. Case-insensitive.
    pattern = "^" + re.escape(query_value).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(pattern, actual_value, re.IGNORECASE) is not None


# ---------------------------------------------------------------------------
# C-ECHO
# ---------------------------------------------------------------------------
def handle_echo(event):
    assoc = event.assoc
    log.info("C-ECHO from calling=%s", _calling_aet(assoc))
    return 0x0000


# ---------------------------------------------------------------------------
# C-FIND: routed by abstract syntax to patient/study Q-R or Modality Worklist
# ---------------------------------------------------------------------------
def handle_find(event):
    abstract = event.context.abstract_syntax
    if abstract == ModalityWorklistInformationFind:
        yield from _handle_mwl(event)
    else:
        yield from _handle_qr(event)


def _handle_qr(event):
    """Patient/Study-root C-FIND over the inmate census."""
    q = event.identifier
    level = getattr(q, "QueryRetrieveLevel", "") or "PATIENT"
    q_name = str(getattr(q, "PatientName", "") or "")
    q_id = str(getattr(q, "PatientID", "") or "")
    log.info("C-FIND level=%s name=%r id=%r", level, q_name, q_id)

    for patient in PATIENTS:
        if event.is_cancelled:
            yield (0xFE00, None)  # Matching terminated due to Cancel
            return
        if not _matches(q_name, patient["PatientName"]):
            continue
        if not _matches(q_id, patient["PatientID"]):
            continue

        resp = Dataset()
        resp.QueryRetrieveLevel = level
        resp.PatientName = patient["PatientName"]
        resp.PatientID = patient["PatientID"]
        resp.PatientBirthDate = patient["PatientBirthDate"]
        resp.PatientSex = patient["PatientSex"]

        if level == "STUDY" and patient.get("study"):
            st = patient["study"]
            resp.StudyInstanceUID = st["study_instance_uid"]
            resp.AccessionNumber = st["accession_number"]
            resp.StudyDescription = st["study_description"]
            resp.ModalitiesInStudy = st["modality"]

        # STAGE 2 FLAG: the named inmate's record over-shares a private tag.
        if patient.get("private_flag"):
            block = resp.private_block(PRIVATE_GROUP, PRIVATE_CREATOR, create=True)
            block.add_new(PRIVATE_ELEMENT, "LO", patient["private_flag"])
            log.info("Returned private-tag flag for %s", patient["PatientName"])

        yield (0xFF00, resp)  # Pending: match follows

    yield (0x0000, None)  # Success: matching complete


def _handle_mwl(event):
    """Modality Worklist C-FIND -> the scheduled order (HL7 handoff seam)."""
    if event.is_cancelled:
        yield (0xFE00, None)
        return

    wl = SCENARIO["worklist"]
    inmate = SCENARIO["inmate"]
    log.info("MWL C-FIND -> order %s / placer %s",
             wl["accession_number"], wl["placer_order_number"])

    resp = Dataset()
    resp.PatientName = inmate["patient_name"]
    resp.PatientID = inmate["patient_id"]
    resp.PatientBirthDate = inmate.get("birth_date", "")
    resp.PatientSex = inmate.get("sex", "")
    resp.AccessionNumber = wl["accession_number"]
    resp.RequestedProcedureID = wl["scheduled_procedure_step_id"]
    resp.RequestedProcedureDescription = wl["requested_procedure_description"]
    # Placer/filler order numbers = the keys the HL7 ORM^O01 stage replays.
    resp.PlacerOrderNumberImagingServiceRequest = wl["placer_order_number"]
    resp.FillerOrderNumberImagingServiceRequest = wl["filler_order_number"]

    sps = Dataset()
    sps.Modality = inmate["study"]["modality"]
    sps.ScheduledStationAETitle = wl["scheduled_station_aet"]
    sps.ScheduledProcedureStepStartDate = wl["scheduled_start_date"]
    sps.ScheduledProcedureStepStartTime = wl["scheduled_start_time"]
    sps.ScheduledProcedureStepDescription = wl["requested_procedure_description"]
    sps.ScheduledProcedureStepID = wl["scheduled_procedure_step_id"]
    resp.ScheduledProcedureStepSequence = [sps]

    yield (0xFF00, resp)
    yield (0x0000, None)


# ---------------------------------------------------------------------------
# Association logging (so organizers can watch solves / enforcement working)
# ---------------------------------------------------------------------------
def _calling_aet(assoc):
    try:
        return assoc.requestor.ae_title
    except Exception:  # pragma: no cover
        return "?"


def _requested_called_aet(assoc):
    try:
        return assoc.requestor.primitive.called_ae_title
    except Exception:  # pragma: no cover
        return "?"


def handle_accepted(event):
    log.info("ASSOC ACCEPTED calling=%s called=%s",
             _calling_aet(event.assoc), _requested_called_aet(event.assoc))


def handle_rejected(event):
    log.info("ASSOC REJECTED calling=%s called=%s (AE enforcement working)",
             _calling_aet(event.assoc), _requested_called_aet(event.assoc))


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
SCENARIO = scenario.load()
PATIENTS = scenario.patients(SCENARIO)


def build_ae():
    xray = SCENARIO["xray"]
    called_aet = xray["called_aet_flag"]

    ae = AE(ae_title=called_aet)
    # STAGE 1 ENFORCEMENT ----------------------------------------------------
    # Reject unless the called AE title matches ours (the flag). This is what
    # nmap dicom-brute enumerates.
    ae.require_called_aet = True
    # Only known fleet devices may be the calling AE title. The player lifts
    # one of these from the WiFi device-inventory page.
    ae.require_calling_aet = list(xray["require_calling_aet"])

    for ctx in (
        Verification,
        PatientRootQueryRetrieveInformationModelFind,
        StudyRootQueryRetrieveInformationModelFind,
        ModalityWorklistInformationFind,
    ):
        ae.add_supported_context(ctx)

    return ae


def main():
    xray = SCENARIO["xray"]
    bind = os.environ.get("XRAY_BIND", "0.0.0.0")
    port = int(xray["listen_port"])

    ae = build_ae()
    handlers = [
        (evt.EVT_C_ECHO, handle_echo),
        (evt.EVT_C_FIND, handle_find),
        (evt.EVT_ACCEPTED, handle_accepted),
        (evt.EVT_REJECTED, handle_rejected),
    ]

    log.info("ER Portable X-ray starting on %s:%d", bind, port)
    log.info("Accepted called AE title (flag 1) enforced; "
             "calling AE allowlist=%s", ae.require_calling_aet)
    ae.start_server((bind, port), evt_handlers=handlers)


if __name__ == "__main__":
    main()
