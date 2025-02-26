FROM jodogne/orthanc-plugins:1.9.7

# Install necessary dependencies
RUN apt-get update && apt-get install -y wget unzip

# Configure Orthanc with intentional misconfigurations
COPY ./orthanc.json /etc/orthanc/orthanc.json

# Populate with sample DICOM images (some containing hidden data)
COPY ./sample-dicom-files /tmp/dicom-files
RUN python /etc/orthanc/import-dicom.py /tmp/dicom-files

# Create user accounts with different privilege levels
RUN /usr/local/sbin/create-users.sh

# Add flag in a specific DICOM file's private tag
COPY ./add-flag-to-dicom.py /tmp/
RUN python /tmp/add-flag-to-dicom.py