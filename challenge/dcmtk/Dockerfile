FROM ubuntu:20.04

# Install DCMTK and dependencies
RUN apt-get update && apt-get install -y dcmtk netcat python3 python3-pip
RUN pip3 install pydicom pynetdicom

# Set up a service that periodically queries the Orthanc server
COPY ./query-service.py /opt/query-service.py
COPY ./start-service.sh /opt/start-service.sh
RUN chmod +x /opt/start-service.sh

# Set up a vulnerable web interface for interacting with DICOM data
COPY ./web-interface /opt/web-interface
WORKDIR /opt/web-interface
RUN pip3 install -r requirements.txt

# Add a second flag in the web interface source code
RUN echo "FLAG{second_flag_hidden_in_source}" >> /opt/web-interface/static/js/obfuscated.js

ENTRYPOINT ["/opt/start-service.sh"]