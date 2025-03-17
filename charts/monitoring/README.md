# 1. Prometheus, Grafana 설치 (+ Thanos)

## 1-1. Prometheus, Grafana 설치

### 1-1-1. Helm Repository에 Prometheus 관련 차트 추가

```powershell
# prometheus 차트 추가
% helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
% helm repo update

# prometheus 관련 repo 확인 -> kube-prometheus-stack 사용 예정
% helm search repo prometheus

NAME                                                    CHART VERSION   APP VERSION     DESCRIPTION
eks/appmesh-prometheus                                  1.0.3           2.13.1          App Mesh Prometheus Helm chart for Kubernetes
**prometheus-community/kube-prometheus-stack              69.4.1          v0.80.0         kube-prometheus-stack collects Kubernetes manif...**
prometheus-community/prometheus                         27.4.0          v3.1.0          Prometheus is a monitoring system and time seri...
prometheus-community/prometheus-adapter                 4.11.0          v0.12.0         A Helm chart for k8s prometheus adapter
prometheus-community/prometheus-blackbox-exporter       9.2.0           v0.25.0         Prometheus Blackbox Exporter
prometheus-community/prometheus-cloudwatch-expo...      0.26.0          0.16.0          A Helm chart for prometheus cloudwatch-exporter
prometheus-community/prometheus-conntrack-stats...      0.5.16          v0.4.25         A Helm chart for conntrack-stats-exporter
prometheus-community/prometheus-consul-exporter         1.0.0           0.4.0           A Helm chart for the Prometheus Consul Exporter
prometheus-community/prometheus-couchdb-exporter        1.0.0           1.0             A Helm chart to export the metrics from couchdb...
prometheus-community/prometheus-druid-exporter          1.1.0           v0.11.0         Druid exporter to monitor druid metrics with Pr...
prometheus-community/prometheus-elasticsearch-e...      6.6.1           v1.8.0          Elasticsearch stats exporter for Prometheus
prometheus-community/prometheus-fastly-exporter         0.5.1           v9.0.1          A Helm chart for the Prometheus Fastly Exporter
																			.
																			.
```

### 1-1-2. Prometheus, Grafana 설치

```powershell
# Git에서 옵션 확인
https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/values.yaml

# prometheus-stack-values.yaml
prometheus:
  enabled: true
  prometheusSpec:
    retention: 30d
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 30Gi
          storageClassName: gp2
    serviceMonitorSelectorNilUsesHelmValues: false  # ServiceMonitorSelector 사용
    serviceMonitorSelector:  # ServiceMonitor를 찾기 위한 조건
      matchLabels:
        release: prometheus                                                     
    serviceMonitorNamespaceSelector: {}  # 모든 Namespace에서 ServiceMonitor를 찾음
    replicas: 1
    additionalScrapeConfigs:
    - job_name: kube-etcd
      kubernetes_sd_configs:
        - role: node
      scheme: https
      tls_config:
        ca_file:   /etc/prometheus/secrets/etcd-client-cert/etcd-ca
        cert_file: /etc/prometheus/secrets/etcd-client-cert/etcd-client
        key_file:  /etc/prometheus/secrets/etcd-client-cert/etcd-client-key
      relabel_configs:
      - action: labelmap

grafana:
  enabled: true
  adminPassword: "admin"
  ingress:
    enabled: true
    ingressClassName: nginx
    annotations:
      nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
      nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
      nginx.ingress.kubernetes.io/force-ssl-redirect: "false"
      nginx.ingress.kubernetes.io/ssl-redirect: "false"
      nginx.ingress.kubernetes.io/proxy-body-size: "0"
      nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    hosts:
      - grafana.gmmt.store
    path:
      - /
  persistence:
    enabled: true
    size: 5Gi
    storageClassName: gp2

# 설치
% helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  -f prometheus-stack-values.yaml
```

### 1-1-3. ServiceMonitor 등록

```powershell
# service-monitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ticketing-service-monitor
  namespace: monitoring
  labels:
    release: prometheus  # 위에서 prometheus.serviceMonitorSelector.matchLabels.release와 일치
spec:
  jobLabel: job  # job을 기준으로 모니터링 그룹화                                                                 
  namespaceSelector: # 모니터링할 Service의 Namespace
    matchNames:
      - default
  endpoints:
    - port: http                                                                  
      interval: 30s
      path: /metrics
  selector:
    matchLabels:
      app: ticketing  # service의 Label                                                            

# ServiceMonitor 등록
% kubectl apply -f service-monitor.yaml
```

- matchLabels는 모니터링할 서비스를 고르는 기준
- jobLabel은 모니터링 그룹화하는 기준

→ app: ticketing Label이 있는 서비스를 모니터링하고, job 라벨의 value에 따라서 그룹화 한다.

### 1-1-4. (모니터링할 기존 프로젝트) Service 설정

```powershell
# event-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-service
  labels:
    {{- include "user.labels" . | nindent 4 }}
    job: {{ .Release.Name }}-service-job  # key = job                                        
    app: ticketing                                                                
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: {{ .Values.service.port }}
      protocol: TCP
      name: http                                                                  
  selector:
    {{- include "user.selectorLabels" . | nindent 4 }}
```

→ 모든 서비스에 적용 후 배포

![image.png](attachment:c07f8202-cb1f-4fa9-b999-97fb4cc1a554:image.png)

### 1-1-5. 연결 확인

(연결을 확인하기 전에, 작성한 Python 프로젝트에 Prometheus 관련 코드를 추가해야 한다.)

```powershell
# 로컬 포트 9090 → 클러스터의 prometheus-operated 서비스의 포트 9090으로 연결
% kubectl port-forward -n monitoring svc/prometheus-operated 9090:9090
```

그리고 http://localhost:9090/targets 접속 후 확인

![image.png](attachment:f48cf604-c29f-4672-afb8-9063538ca5ef:image.png)

## 1-2. Thanos 설치

### 1-2-1. Thanos Sidecar, ThanosService 설치

<1-1-2. Prometheus, Grafana 설치>에서 작성 prometheus-stack-values.yaml에 Thanos 관련 옵션을 추가하면 된다. 예제에서는 아래 두가지를 설치한다.

- Thanos Sidecar
    - Prometheus 내부에 설치
    - Prometheus의 데이터를 장기 보관하기 위해 객체 스토리지(S3)에 업로드하는 역할 수행
- ThanosService
    - Prometheus의 Thanos gRPC 서비스를 외부에서 접근할 수 있또록 Service 리소스 생성
    - HTTP 통신도 가능하나 기본적으로 성능이 좋은 gRPC 통신을 사용

```powershell
# Git에서 옵션 확인
https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/values.yaml

# prometheus-stack-values.yaml
prometheus:
  enabled: true
  prometheusSpec:
    disableCompaction: true # thanos 사용을 위해 압축 기능 사용 x
    retention: 30d
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 30Gi
          storageClassName: gp2
    serviceMonitorSelectorNilUsesHelmValues: false
    serviceMonitorSelector:
      matchLabels:
        release: prometheus
    serviceMonitorNamespaceSelector: {}
    replicas: 1
    additionalScrapeConfigs:
    - job_name: kube-etcd
      kubernetes_sd_configs:
        - role: node
      scheme: https
      tls_config:
        ca_file:   /etc/prometheus/secrets/etcd-client-cert/etcd-ca
        cert_file: /etc/prometheus/secrets/etcd-client-cert/etcd-client
        key_file:  /etc/prometheus/secrets/etcd-client-cert/etcd-client-key
      relabel_configs:
      - action: labelmap
    thanos:
      image: quay.io/thanos/thanos:v0.28.1
      objectStorageConfig:
        existingSecret:
          name: thanos-objstore-config
          key: thanos.yaml

  thanosService:
    enabled: true
    annotations: {}
    labels: {}
    externalTrafficPolicy: Cluster
    type: ClusterIP
    portName: grpc
    port: 10901
    targetPort: "grpc"
    httpPortName: http
    httpPort: 10902
    targetHttpPort: "http"
    clusterIP: ""
    nodePort: 30901
    httpNodePort: 30902
    
grafana:
  enabled: true
  adminPassword: "admin"
  ingress:
    enabled: true
    ingressClassName: alb
    annotations:
      alb.ingress.kubernetes.io/load-balancer-name: main-alb
      alb.ingress.kubernetes.io/target-type: ip
      alb.ingress.kubernetes.io/group.name: ingress-group.main-group
      alb.ingress.kubernetes.io/scheme: internet-facing
      alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:ap-northeast-2:206177862976:certificate/89e2b200-d921-4c29-b6e5-5a51f5a4d2be
      alb.ingress.kubernetes.io/listen-ports: '[{"HTTP":80}, {"HTTPS":443}]'
      alb.ingress.kubernetes.io/ssl-redirect: '443'
      alb.ingress.kubernetes.io/healthcheck-path: /health
      alb.ingress.kubernetes.io/success-codes: '200'
    hosts:
      - grafana.gmmt.store
    paths:
      - /

  persistence:
    enabled: true
    size: 5Gi
    storageClassName: gp2
  additionalDataSources:
    # - name: Prometheus
    #   type: prometheus
    #   access: proxy
    #   url: http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090
    #   jsonData:
    #     timeInterval: "5s"

		# Prometheus에 연결돼있던 것을 Thanos로 수정
    - name: Thanos
      type: prometheus
      access: proxy
      url: http://thanos-query.thanos.svc.cluster.local:9090
      jsonData:
        timeInterval: "5s"

    - name: Loki
      type: loki
      access: proxy
      url: http://loki-gateway.monitoring.svc.cluster.local
      jsonData:
        timeout: 30
  
```

### 1-2-2. Thanos Query, Receive, Store 배포

- Thanos Namespace 생성

```powershell
% kubectl create namespace thanos
```

- Secret 등록

```powershell
# thanos-storage-config.yaml
type: s3
config:
  bucket: thanos-store #S3 Bucket Name
  endpoint: s3.<region>.amazonaws.com #S3 Regional endpoint
  access_key: <aws-account-id>
  secret_key: <aws-account-secret>

# secret 등록   
kubectl -n monitoring create secret generic thanos-objstore-config \
  --from-file=thanos.yaml=thanos-storage-config.yaml
```

- Thanos Git 소스코드 다운로드

```powershell
% git clone https://github.com/thanos-io/kube-thanos
```

- 설치

```powershell
# kube-thanos/manifests/thanos-query-deployment.yaml 수정
 - args:
   - query
   - --grpc-address=0.0.0.0:10901
   - --http-address=0.0.0.0:9090
   - --log.level=info
   - --log.format=logfmt
   - --query.replica-label=prometheus_replica
   - --query.replica-label=rule_replica
   - --endpoint=dnssrv+_grpc._tcp.thanos-store.thanos.svc.cluster.local:10901
   - --endpoint=dnssrv+_grpc._tcp.thanos-receive-ingestor-default.thanos.svc.cluster.local:10901
   # thanos-store, prometheus-thanos 주소 추가
   - --store=dnssrv+_grpc._tcp.thanos-store.thanos.svc.cluster.local:10901
   - --store=dnssrv+_grpc._tcp.prometheus-kube-prometheus-thanos-discovery.prometheus.svc.cluster.local:10901
   - --query.auto-downsampling
  
# 설치 
% kubectl apply -f manifests -n thanos
```

# 2. Loki 설치

참고 사이트: https://grafana.com/docs/loki/latest/setup/install/helm/deployment-guides/aws/#defining-iam-roles-and-policies

### 2-1. AWS S3 생성 및 라이프사이클 설정

- `loki-ticketing-chunks`: 이 버킷은 Loki의 **chunk** 데이터를 저장하는 데 사용됩니다. Loki는 로그 데이터를 **chunk** 단위로 처리하고, 이 chunk는 S3에 저장됩니다. 이 버킷은 Loki의 **ingester** 컴포넌트가 로그 데이터를 처리하고 S3로 전송하는 데 사용됩니다.
- `loki-ticketing-rulers`: 이 버킷은 Loki의 **Ruler** 컴포넌트가 사용하는 규칙과 관련된 데이터를 저장하는 데 사용됩니다. Ruler는 **alerting rules**와 **recording rules**를 관리하며, 이 규칙들은 S3에 저장됩니다.

```powershell
% aws s3api create-bucket \
  --bucket loki-ticketing-chunks \
  --region ap-northeast-2 \
  --create-bucket-configuration LocationConstraint=ap-northeast-2
  
% aws s3api create-bucket \
  --bucket loki-ticketing-rulers \
  --region ap-northeast-2 \
  --create-bucket-configuration LocationConstraint=ap-northeast-2
  
# 생성 확인
% aws s3api list-buckets
```

- s3 라이프사이클 설정

```powershell
# s3-lifecycle-conf.json
{
  "Rules": [
      {
          "ID": "LogArchivingRule",
          "Filter": {
              "ObjectSizeGreaterThan": 0
          },
          "Status": "Enabled",
          "Transitions": [
              {
                  "Days": 7,
                  "StorageClass": "GLACIER"
              }
          ],
          "Expiration": {
              "Days": 187
          }
      }
  ]
}

# 정책 적용
% aws s3api put-bucket-lifecycle-configuration \
  --bucket loki-ticketing-chunks \
  --lifecycle-configuration file://s3-lifecycle-conf.json \
  --region ap-northeast-2
```

### 2-2. Loki S3 접근 권한 설정

- 정책 등록

```powershell
# loki-s3-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "LokiStorage",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::loki-ticketing-chunks",
                "arn:aws:s3:::loki-ticketing-chunks/*",
                "arn:aws:s3:::loki-ticketing-rulers",
                "arn:aws:s3:::loki-ticketing-rulers/*"
            ]
        }
    ]
}

# 정책 등록
% aws iam create-policy \
  --policy-name LokiS3AccessPolicy \
  --policy-document file://loki-s3-policy.json
```

- 역할 등록

```powershell
# trust-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::206177862976:oidc-provider/oidc.eks.ap-northeast-2.amazonaws.com/id/81CB5AE2BA42153B71C0D4112DF0D5BA"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "oidc.eks.ap-northeast-2.amazonaws.com/id/81CB5AE2BA42153B71C0D4112DF0D5BA:sub": "system:serviceaccount:monitoring:loki",
                    "oidc.eks.ap-northeast-2.amazonaws.com/id/81CB5AE2BA42153B71C0D4112DF0D5BA:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}

# 역할 등록
% aws iam create-role \
  --role-name LokiServiceAccountRole \
  --assume-role-policy-document file://trust-policy.json
```

- 정책-역할 연결

```powershell
% aws iam attach-role-policy \
  --role-name LokiServiceAccountRole \
  --policy-arn arn:aws:iam::206177862976:policy/LokiS3AccessPolicy
```

### 2-3. Loki Authentication 설정

```powershell
# htpasswd 파일 생성 및 Loki 사용자 추가
% htpasswd -c .htpasswd loki-user

# Loki 기본 인증 시크릿 생성
% kubectl create secret generic loki-basic-auth --from-file=.htpasswd -n monitoring

# Loki Canary 기본 인증 시크릿 생성
% kubectl create secret generic canary-basic-auth \
  --from-literal=username=loki-user \
  --from-literal=password=loki-user \
  -n monitoring
```

### 2-4. Loki 설치

```powershell
# loki-values.yaml
loki:
   schemaConfig:
     configs:
       - from: "2024-04-01"
         store: tsdb
         object_store: s3
         schema: v13
         index:
           prefix: loki_index_
           period: 24h
   storage_config:
     aws:
       region: ap-northeast-2
       bucketnames: loki-ticketing-chunks
       s3forcepathstyle: false
   ingester:
       chunk_encoding: snappy
   pattern_ingester:
       enabled: true
   limits_config:
     allow_structured_metadata: true
     volume_enabled: true
     retention_period: 672h # 28 days retention
   compactor:
     retention_enabled: true 
     delete_request_store: s3
   ruler:
    enable_api: true
    storage:
      type: s3
      s3:
        region: ap-northeast-2
        bucketnames: loki-ticketing-rulers
        s3forcepathstyle: false
      alertmanager_url: http://prom:9093 # The URL of the Alertmanager to send alerts (Prometheus, Mimir, etc.)

   querier:
      max_concurrent: 4

   storage:
      type: s3
      bucketNames:
        chunks: "loki-ticketing-chunks"
        ruler: "loki-ticketing-rulers"
        # admin: "<Insert s3 bucket name>" # Your actual S3 bucket name (loki-aws-dev-admin) - GEL customers only
      s3:
        region: ap-northeast-2
        #insecure: false
      # s3forcepathstyle: false

serviceAccount:
 create: true
 annotations:
   "eks.amazonaws.com/role-arn": "arn:aws:iam::206177862976:role/LokiServiceAccountRole" # The service role you created

deploymentMode: Distributed

ingester:
 replicas: 3
 zoneAwareReplication:
  enabled: false

querier:
 replicas: 3
 maxUnavailable: 2

queryFrontend:
 replicas: 2
 maxUnavailable: 1

queryScheduler:
 replicas: 2

distributor:
 replicas: 3
 maxUnavailable: 2
compactor:
 replicas: 1

indexGateway:
 replicas: 2
 maxUnavailable: 1

ruler:
 replicas: 1
 maxUnavailable: 1

# This exposes the Loki gateway so it can be written to and queried externaly
gateway:
 service:
   type: ClusterIP
 basicAuth: 
     enabled: true
     existingSecret: loki-basic-auth

# Since we are using basic auth, we need to pass the username and password to the canary
lokiCanary:
  extraArgs:
    - -pass=$(LOKI_PASS)
    - -user=$(LOKI_USER)
  extraEnv:
    - name: LOKI_PASS
      valueFrom:
        secretKeyRef:
          name: canary-basic-auth
          key: password
    - name: LOKI_USER
      valueFrom:
        secretKeyRef:
          name: canary-basic-auth
          key: username

# Enable minio for storage
minio:
 enabled: false

backend:
 replicas: 0
read:
 replicas: 0
write:
 replicas: 0

singleBinary:
 replicas: 0

# 설치
helm upgrade --install loki grafana/loki \
  --namespace monitoring --create-namespace \
  -f loki-values.yaml
```

### 2-5. 연결 확인

```powershell

```

# 3. Promtail 설치

### 3-1. Promtail 설치

```powershell
# promtail-values.yaml
config:
  enabled: true
  logLevel: info
  logFormat: logfmt

  serverPort: 3101

  # loki gateway 주소
  clients:
    - url: http://loki-gateway/loki/api/v1/push

  positions:
    filename: /run/promtail/positions.yaml

# 모든 Node에 등록이 돼야하므로 Daemonset으로 설정
daemonset:
  enabled: true

# 프로젝트의 Cluster에는 taint가 설정돼있으므로 Toleration 설정 필요
tolerations:
  - key: "karpenter.sh/controller"
    operator: "Exists"
    effect: "NoSchedule"

annotations: {}
podLabels: {}

podAnnotations: {}
rbac:
  create: true

serviceAccount:
  create: true

# 설치
helm upgrade --install promtail grafana/loki \
  --namespace monitoring --create-namespace \
  -f promtail-values.yaml
```