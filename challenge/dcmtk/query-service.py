#!/usr/bin/env python3
import time
import random
from pynetdicom import AE
from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind

# This service periodically queries the Orthanc server
# Contains an intentional vulnerability in the query handling

def query_orthanc():
    ae = AE(ae_title="DMCTK")
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    
    # Connect to Orthanc
    assoc = ae.associate("192.168.10.1", 4242)
    
    if assoc.is_established:
        # Query with different parameters each time
        # Some combinations will reveal hidden studies
        query = {
            "PatientName": "*",
            "StudyDescription": "*",
            "QueryRetrieveLevel": "STUDY",
            "SpecificCharacterSet": random.choice(["ISO_IR 100", "ISO_IR 192"])
        }
        
        responses = assoc.send_c_find(query, PatientRootQueryRetrieveInformationModelFind)
        
        for (status, dataset) in responses:
            # Process response
            # Contains a vulnerability in handling certain response types
            pass
            
        assoc.release()

while True:
    query_orthanc()
    # Sleep between 30-60 seconds
    time.sleep(random.randint(30, 60))