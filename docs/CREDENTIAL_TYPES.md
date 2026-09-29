# 凭据检测类型（v0.6）

- AWS Access Key ID / AWS AK-SK Pair
- Huawei Cloud AK/SK Pair
- Alibaba Cloud AccessKey ID / AK-SK Pair
- Tencent Cloud SecretId / SecretId-SecretKey Pair
- SSH Private Key / PEM Private Key
- GitHub Token
- Slack-style Token
- JWT
- Database URI
- OAuth Client Secret
- Generic API key / secret / password / token assignment

检测结合格式、entropy、上下文、路径和 provider pair 关联；JSON/YAML/ENV 等带引号键值均支持。
