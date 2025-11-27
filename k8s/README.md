# Kubernetes Deployment Guide

## Prerequisites

- Kubernetes cluster (v1.24+)
- `kubectl` configured
- Container registry access
- PostgreSQL database (external or in-cluster)

## Quick Start

### 1. Build and Push Docker Image

```bash
# Build the image
docker build -t your-registry/web-ssh-backend:v1.0.0 .

# Push to registry
docker push your-registry/web-ssh-backend:v1.0.0
```

### 2. Update Configuration

Edit the following files with your values:

**`configmap.yaml`:**
- `google-redirect-url`: Your OAuth callback URL
- `frontend-url`: Your frontend domain(s)

**`deployment.yaml`:**
- Update `image:` with your registry path

**`ingress.yaml`:**
- Update `host:` with your domain
- Configure TLS if needed

### 3. Create Secrets

**Option A: Using kubectl (Recommended)**
```bash
kubectl create secret generic web-ssh-secrets \
  --from-literal=db-path="postgres://user:pass@host:5432/db?sslmode=disable" \
  --from-literal=google-client-id="your-client-id" \
  --from-literal=google-client-secret="your-secret" \
  --from-literal=jwt-secret="your-jwt-secret-min-32-chars" \
  --from-literal=encryption-key="your-32-byte-encryption-key-1234"
```

**Option B: Using YAML file**
```bash
# Create secret.yaml from example (DO NOT commit to git!)
cp secret.yaml.example secret.yaml
# Edit secret.yaml with base64 encoded values
# To encode: echo -n "your-value" | base64
kubectl apply -f secret.yaml
```

### 4. Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f k8s/

# Or apply individually
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml  # If using YAML method
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml
```

### 5. Verify Deployment

```bash
# Check pods
kubectl get pods -l app=web-ssh-backend

# Check service
kubectl get svc web-ssh-backend

# Check ingress
kubectl get ingress web-ssh-backend

# View logs
kubectl logs -l app=web-ssh-backend -f

# Check HPA status
kubectl get hpa web-ssh-backend
```

## Manifests Overview

| File | Description |
|------|-------------|
| `deployment.yaml` | Main application deployment with 2 replicas |
| `service.yaml` | ClusterIP service for internal communication |
| `configmap.yaml` | Non-sensitive configuration |
| `secret.yaml.example` | Example for sensitive data (create actual `secret.yaml`) |
| `ingress.yaml` | External access configuration |
| `hpa.yaml` | Auto-scaling based on CPU/memory |

## Configuration

### Environment Variables

All environment variables are injected from ConfigMap and Secrets:

| Variable | Source | Description |
|----------|--------|-------------|
| `PORT` | Hardcoded | Application port (8080) |
| `DB_PATH` | Secret | PostgreSQL connection string |
| `GOOGLE_CLIENT_ID` | Secret | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Secret | Google OAuth secret |
| `GOOGLE_REDIRECT_URL` | ConfigMap | OAuth callback URL |
| `JWT_SECRET` | Secret | JWT signing secret |
| `ENCRYPTION_KEY` | Secret | Server password encryption key |
| `FRONTEND_URL` | ConfigMap | Frontend URL(s) |

### Resource Limits

Default resource configuration:
- **Requests:** 100m CPU, 64Mi memory
- **Limits:** 500m CPU, 256Mi memory

Adjust in `deployment.yaml` based on your needs.

### Auto-scaling

HPA configuration:
- **Min replicas:** 2
- **Max replicas:** 10
- **CPU target:** 70%
- **Memory target:** 80%

## Production Checklist

- [ ] Update image registry in `deployment.yaml`
- [ ] Configure proper domain in `ingress.yaml`
- [ ] Enable TLS/HTTPS in `ingress.yaml`
- [ ] Create secrets with strong values
- [ ] Set up external PostgreSQL database
- [ ] Configure resource limits based on load testing
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy for database
- [ ] Review security policies
- [ ] Test health checks and auto-scaling

## Useful Commands

**Update deployment:**
```bash
# Update image
kubectl set image deployment/web-ssh-backend \
  web-ssh-backend=your-registry/web-ssh-backend:v1.0.1

# Or edit directly
kubectl edit deployment web-ssh-backend
```

**Scale manually:**
```bash
kubectl scale deployment web-ssh-backend --replicas=5
```

**Restart pods:**
```bash
kubectl rollout restart deployment web-ssh-backend
```

**View rollout status:**
```bash
kubectl rollout status deployment web-ssh-backend
```

**Rollback deployment:**
```bash
kubectl rollout undo deployment web-ssh-backend
```

**Port forward for testing:**
```bash
kubectl port-forward svc/web-ssh-backend 8080:80
```

**Execute commands in pod:**
```bash
kubectl exec -it deployment/web-ssh-backend -- /bin/sh
```

**View events:**
```bash
kubectl get events --sort-by='.lastTimestamp'
```

## Troubleshooting

**Pods not starting:**
```bash
kubectl describe pod -l app=web-ssh-backend
kubectl logs -l app=web-ssh-backend --previous
```

**Database connection issues:**
- Verify `DB_PATH` secret is correct
- Check network policies
- Ensure database is accessible from cluster

**Ingress not working:**
```bash
kubectl describe ingress web-ssh-backend
# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx
```

**Health checks failing:**
- Check if `/api/me` endpoint requires authentication
- Adjust `initialDelaySeconds` if app takes longer to start
- Review application logs

## Security Best Practices

1. **Never commit secrets to git** - Add `secret.yaml` to `.gitignore`
2. **Use strong secrets** - Generate cryptographically secure values
3. **Enable RBAC** - Limit service account permissions
4. **Use network policies** - Restrict pod-to-pod communication
5. **Enable TLS** - Use cert-manager for automatic certificate management
6. **Scan images** - Use tools like Trivy or Snyk
7. **Keep images updated** - Regularly update base images and dependencies
8. **Use read-only filesystem** - Where possible (currently disabled for app needs)

## Monitoring

Consider adding:
- Prometheus metrics endpoint
- Grafana dashboards
- Alert rules for critical metrics
- Log aggregation (ELK, Loki, etc.)
- Distributed tracing (Jaeger, Zipkin)
