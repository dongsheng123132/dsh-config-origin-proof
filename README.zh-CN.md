# DSH Config Origin Proof

面向 DeepSeek Harness 配置来源归属的证据层：验证一份显式、脱敏的来源记录，给出优先级域、各层观察、实际胜出来源、被遮蔽来源和值摘要，并在高优先级来源未观察时失败闭合。

它不重做 DSH 配置组合器、不采集现场配置，也不替代策略漂移或安装闭包证明。DSH 自带的 `--dump-config` 仍是组合权威；本插件只把可信生产者形成的结构化记录变成可复核收据。`dsh-policy-drift-proof` 回答前后策略是否变化，`dsh-profile-lock-proof` 回答安装闭包是否固定，本项目回答记录中的配置由哪一层赢得以及为什么。

拒绝原始值、秘密、凭据、prompt、消息和正文形字段；报告只含稳定 ID、SHA-256 与判决。DSH/CLI 只读取 workspace 内显式文件并向显式 `artifactDir` 写内容寻址报告；MCP 只处理有界内联 JSON，不读写文件、不联网、不启动子进程。

DSH 工具：`dsh_config_origin_inspect`、`dsh_config_origin_verify`。MIT。
