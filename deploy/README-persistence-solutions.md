# Trustee 服务数据持久化解决方案

## 概述

本文档提供了5种不同的数据持久化解决方案，用于解决容器化业务服务在升级、重启、迁移等运维操作中的数据丢失问题。所有方案都不需要修改业务服务程序本身，通过sidecar模式实现数据持久化。

## 方案对比

| 方案 | 复杂度 | 可靠性 | 性能 | 适用场景 | 依赖 |
|------|--------|--------|------|----------|------|
| Sidecar备份 | 低 | 中 | 高 | 单节点、简单场景 | 无 |
| 外部存储 | 中 | 高 | 中 | 多节点、高可用 | Redis/MinIO |
| Git版本化 | 中 | 高 | 中 | 需要版本控制 | Git仓库 |
| 网络文件系统 | 中 | 高 | 中 | 传统环境 | NFS/SFTP |
| 数据库存储 | 高 | 高 | 低 | 结构化数据 | PostgreSQL/SQLite |

## 方案一：基于Sidecar的本地备份方案

### 特点
- **优点**：实现简单，无外部依赖，性能好
- **缺点**：数据仍在本地，节点故障时数据丢失
- **适用场景**：单节点部署，对数据可靠性要求不高

### 部署步骤
```bash
# 1. 应用配置
kubectl apply -f data-persistence-sidecar.yml

# 2. 验证部署
kubectl get pods -l app=trustee-service
kubectl logs -f deployment/trustee-service-with-persistence -c data-backup-sidecar
```

### 配置说明
- 备份间隔：默认5分钟，可通过环境变量调整
- 备份保留：最近10个备份文件
- 恢复机制：Pod启动时自动从最新备份恢复

## 方案二：基于外部存储服务的方案

### 特点
- **优点**：高可用，支持多节点，数据安全
- **缺点**：需要额外的存储服务
- **适用场景**：生产环境，多副本部署

### Redis存储版本
```bash
# 1. 部署Redis存储服务
kubectl apply -f external-storage-solution.yml

# 2. 等待Redis就绪
kubectl wait --for=condition=ready pod -l app=redis-storage

# 3. 部署业务服务
kubectl get deployment trustee-with-external-storage
```

### MinIO存储版本
需要修改配置文件中的环境变量：
```yaml
env:
- name: STORAGE_TYPE
  value: "minio"
- name: MINIO_ENDPOINT
  value: "your-minio-endpoint"
- name: MINIO_ACCESS_KEY
  value: "your-access-key"
- name: MINIO_SECRET_KEY
  value: "your-secret-key"
```

## 方案三：基于Git仓库的版本化方案

### 特点
- **优点**：版本控制，变更历史，支持回滚
- **缺点**：不适合频繁变化的大文件
- **适用场景**：配置文件、小型数据文件

### 部署步骤
```bash
# 1. 创建Git仓库（可选）
# 如果使用远程仓库，需要配置GIT_REMOTE_URL

# 2. 修改配置
# 编辑 git-based-persistence.yml 中的 GIT_REMOTE_URL

# 3. 部署服务
kubectl apply -f git-based-persistence.yml

# 4. 查看同步日志
kubectl logs -f deployment/trustee-with-git-persistence -c git-backup-sidecar
```

### Git认证配置
如果使用私有仓库，需要配置认证信息：
```bash
# 创建包含认证信息的Secret
kubectl create secret generic git-credentials \
  --from-literal=username=your-username \
  --from-literal=password=your-token
```

## 方案四：基于网络文件系统的方案

### 特点
- **优点**：传统可靠，易于管理
- **缺点**：需要网络文件系统基础设施
- **适用场景**：传统IT环境，已有NFS/SFTP服务

### NFS版本部署
```bash
# 1. 修改NFS配置
# 编辑 network-fs-persistence.yml 中的 NFS_SERVER 和 NFS_PATH

# 2. 部署服务
kubectl apply -f network-fs-persistence.yml

# 3. 验证NFS挂载
kubectl exec -it deployment/trustee-with-nfs-persistence -c nfs-backup-sidecar -- df -h
```

### SFTP版本部署
```bash
# 1. 配置SFTP认证
kubectl create secret generic sftp-credentials \
  --from-literal=host=your-sftp-host \
  --from-literal=username=your-username \
  --from-literal=password=your-password

# 2. 部署服务
kubectl apply -f network-fs-persistence.yml
```

## 方案五：基于数据库的存储方案

### 特点
- **优点**：结构化存储，支持查询，事务保证
- **缺点**：性能较低，适合小文件
- **适用场景**：结构化数据，需要查询功能

### PostgreSQL版本
```bash
# 1. 部署PostgreSQL
kubectl apply -f database-persistence.yml

# 2. 等待数据库就绪
kubectl wait --for=condition=ready pod -l app=postgres-storage

# 3. 验证数据同步
kubectl logs -f deployment/trustee-with-database-persistence -c db-sync-sidecar
```

### SQLite版本（单实例）
```bash
# 部署SQLite版本
kubectl apply -f database-persistence.yml
kubectl get deployment trustee-with-sqlite-persistence
```

## 运维操作指南

### 数据恢复
```bash
# 方案一：从备份恢复
kubectl exec -it pod-name -c data-backup-sidecar -- /scripts/sync-data.sh init

# 方案二：从Redis恢复
kubectl exec -it pod-name -c data-sync-sidecar -- python /scripts/storage-adapter.py

# 方案三：从Git恢复
kubectl exec -it pod-name -c git-backup-sidecar -- /scripts/git-sync.sh restore
```

### 监控和日志
```bash
# 查看备份日志
kubectl logs -f deployment/your-deployment -c backup-sidecar

# 查看数据同步状态
kubectl exec -it pod-name -c sidecar-container -- ps aux
```

### 故障排除

#### 常见问题
1. **备份失败**：检查存储服务连接和权限
2. **恢复失败**：确认备份文件存在和格式正确
3. **性能问题**：调整同步间隔和批处理大小

#### 调试命令
```bash
# 检查容器状态
kubectl describe pod pod-name

# 查看详细日志
kubectl logs pod-name -c container-name --previous

# 进入容器调试
kubectl exec -it pod-name -c container-name -- /bin/sh
```

## 性能优化建议

### 通用优化
1. **调整同步间隔**：根据数据变化频率调整
2. **文件过滤**：排除临时文件和日志文件
3. **压缩传输**：启用数据压缩减少网络开销

### 方案特定优化
- **Redis方案**：使用Redis集群提高性能
- **Git方案**：使用.gitignore排除大文件
- **数据库方案**：优化数据库连接池和索引

## 安全考虑

### 数据加密
```bash
# 为敏感数据创建加密的Secret
kubectl create secret generic encryption-key \
  --from-literal=key=$(openssl rand -base64 32)
```

### 网络安全
- 使用TLS加密传输
- 配置网络策略限制访问
- 定期轮换认证凭据

## 选择建议

### 推荐方案选择流程
1. **评估数据重要性**：关键数据选择高可靠性方案
2. **考虑基础设施**：根据现有基础设施选择兼容方案
3. **性能要求**：高性能要求选择本地备份或Redis方案
4. **运维复杂度**：简单环境选择Sidecar方案

### 生产环境推荐
- **高可用场景**：方案二（Redis/MinIO）
- **版本控制需求**：方案三（Git）
- **传统环境**：方案四（NFS）
- **简单部署**：方案一（Sidecar）

## 迁移指南

### 从现有方案迁移
1. **备份当前数据**
2. **部署新的持久化方案**
3. **验证数据完整性**
4. **切换流量**
5. **清理旧资源**

### 方案间切换
不同方案间可以通过数据导出/导入实现切换，具体步骤请参考各方案的恢复操作。 