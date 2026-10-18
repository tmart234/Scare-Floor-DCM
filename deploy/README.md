# Deploying Scare Floor DCM (stages 1–2)

The DICOM phase is **networking-first**: players must reach a raw TCP port with
`nmap` and `findscu`. Any front door that only proxies HTTP will not work for
this challenge. Production target is **Kubernetes**, one instance per team.

## 1. Build the image (context = repo root)

```bash
docker build -f challenge/xray-scp/Dockerfile -t <registry>/scare-floor-xray-scp:v1 .
docker push <registry>/scare-floor-xray-scp:v1
```

## 2. Local smoke test (no cluster)

```bash
docker compose -f deploy/docker-compose.yml up --build
nmap -p 11112 --script dicom-ping 127.0.0.1      # -> Called AET check enabled
```

Or without Docker, straight from the repo:

```bash
pip install -r challenge/xray-scp/requirements.txt
python challenge/xray-scp/xray_scp.py            # listens on :11112
```

## 3. Per-team Kubernetes deploy

Each team gets its own namespace so brute-force traffic and flags are isolated.

```bash
TEAM=team-07

# namespace + real flags (keep flags.secret.yaml OUT of git)
kubectl create namespace $TEAM
cp deploy/k8s/flags.secret.example.yaml deploy/k8s/flags.secret.yaml
#   edit FLAG1_AE_TITLE (<=16 chars) and FLAG2_PRIVATE per team/event
kubectl -n $TEAM apply -f deploy/k8s/flags.secret.yaml

# point the image at your registry and deploy
cd deploy/k8s
kustomize edit set image REGISTRY/scare-floor-xray-scp=<registry>/scare-floor-xray-scp:v1
kubectl -n $TEAM apply -k .

# find the external DICOM address to hand players
kubectl -n $TEAM get svc xray-scp
```

### Exposing the DICOM port
- **Cloud (default):** `xray-scp` Service is `type: LoadBalancer` → each team
  gets its own external IP. Players use `nmap -p 11112 <EXTERNAL-IP>`.
- **Bare-metal / no cloud LB:** uncomment the NodePort patch in
  `kustomization.yaml`; players use `nmap -p <nodePort> <node-ip>` (the DICOM
  endpoint is still logically 11112 inside the pod).

> The container runs non-root, read-only rootfs, all caps dropped. Port 11112 is
> unprivileged, so no extra capabilities are needed.

## 4. Flag rotation per event
Flags live only in the `scare-floor-flags` Secret, never in the image. To rotate:

```bash
kubectl -n $TEAM create secret generic scare-floor-flags \
  --from-literal=FLAG1_AE_TITLE='BHV_XR_<new>' \
  --from-literal=FLAG2_PRIVATE='BHV{<new>}' \
  --dry-run=client -o yaml | kubectl -n $TEAM apply -f -
kubectl -n $TEAM rollout restart deploy/xray-scp
```

`FLAG1_AE_TITLE` must be ≤16 bytes (DICOM AE-title limit). It is automatically
added to the service-AET pool, so the WiFi inventory wordlist stays in sync.

## 5. Keep the WiFi inventory page in sync
The WiFi stage serves `inventory/device-inventory.html`. Regenerate it from the
same scenario (with the same flag env) so the leaked wordlist contains the live
AE title:

```bash
FLAG1_AE_TITLE='BHV_XR_<new>' python inventory/gen_inventory.py
```

## 6. Sanity check a live instance
```bash
TARGET=<external-ip>
nmap -p 11112 --script dicom-ping $TARGET
nmap -p 11112 --script dicom-brute \
  --script-args dicom.calling_aet=XRAY_ER_01,passdb=<(python inventory/gen_inventory.py --wordlist) $TARGET
echoscu -aet XRAY_ER_01 -aec <flag1> $TARGET 11112
```
