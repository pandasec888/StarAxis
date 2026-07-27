# StarAxis浏览器扩展

当前实现 Chrome、Edge 和 Firefox 桌面版的 V2.0“点击后填充”，不包含 Safari。

## 开发构建

```bash
pnpm build:extension
```

产物位于：

- `apps/browser-extension/dist/chrome`
- `apps/browser-extension/dist/edge`
- `apps/browser-extension/dist/firefox`
- `target/release/vault-extension-host`

## 本地加载与 Native Messaging

1. 在目标浏览器的扩展管理页加载对应 `dist` 目录。
2. 记录 Chrome/Edge 显示的 32 位扩展 ID。
3. 注册本机 host：

```bash
node apps/browser-extension/scripts/native-host.mjs \
  --host target/release/vault-extension-host \
  --chrome-id <Chrome扩展ID> \
  --edge-id <Edge扩展ID> \
  --firefox-id browser@staraxis.local
```

4. 启动StarAxis桌面端并解锁保险库。
5. 点击扩展中的“开始配对”，在桌面端“浏览器扩展”页面核对六位数字并允许。

卸载本机 host 清单时使用相同参数并追加 `--remove`。安装器采用原子替换，重复安装和重复卸载都安全。

如需在临时目录验证清单而不修改真实浏览器配置，可追加 `--home <临时目录>`。

扩展只在顶层 HTTPS 页面检测用户提交的单密码登录表单；不读取 HTTP、iframe、浏览历史或 Cookie。捕获的密码仅在扩展后台内存中短暂保留，不写入扩展存储，并且只有用户点击“保存”或“更新”后才通过加密本机通道写入已解锁的StarAxis保险库。无痕窗口、页面加载自动填充仍不支持。
