# B站私信自动回复机器人

## 项目简介

这是一个基于Node.js开发的Bilibili私信自动回复机器人，通过集成微信对话开放平台API，实现B站私信的自动化回复功能。

## 功能特性

1. **B站私信自动回复**：实时监听并自动回复B站私信。
2. **微信对话开放平台集成**：利用微信对话开放平台API进行自然语言处理和回复生成。
3. **请求重试机制**：自动重试失败的HTTP请求，提高系统的容错性。
4. **频率限制**：控制请求速率，避免触发B站API的限制。
5. **消息加密解密**：支持AES加密解密，确保通信安全。
6. **定时任务**：定期轮询未读私信，实现实时响应。

## 技术栈

- **Node.js**: 运行环境
- **Axios**: HTTP客户端
- **crypto**: 加密解密模块
- **dotenv**: 环境变量管理
- **axios-retry**: 请求重试库
- **rate-limiter-flexible**: 频率限制库

## 环境变量配置

在 `.env` 文件中配置以下环境变量：

```env
WX_APPID=微信对话开放平台的APPID
WX_APPSECRET=微信对话开放平台的Token
ENCODING_AES_KEY=微信对话开放平台的Encoding AESKey
WX_API_BASE_URL=微信API基础URL
CACHE_EXPIRY=Token缓存过期时间（毫秒）
B_API_BASE_URL=B站API基础URL
B_COOKIES=B站登录后的Cookies
```

## 使用示例

1. **安装依赖**：
   ```bash
   npm install
   ```

2. **配置环境变量**：
   在根目录下创建`.env`文件，并配置所需环境变量。

3. **启动项目**：
   ```bash
   node index.js
   ```

## 后续优化规划

1. **增加扫码登录B站功能**：
   - 集成B站扫码登录API，实现无Cookie登录。
   - 自动处理二维码生成、扫描和验证流程。

2. **增加日志记录**：
   - 记录关键操作和错误信息，便于排查问题。


## 部署与运行

1. **安装Node.js**：确保已安装Node.js环境。
2. **克隆仓库**：
   ```bash
   git clone https://github.com/yourusername/bilibili-auto-reply-bot.git
   cd bilibili-auto-reply-bot
   ```
3. **安装依赖**：
   ```bash
   npm install
   ```
4. **配置环境变量**：创建`.env`文件并配置所需环境变量。
5. **启动项目**：
   ```bash
   node index.js
   ```

## 注意事项

1. **环境变量配置**：确保`.env`文件中的环境变量正确配置，尤其是B站Cookies和微信对话开放平台的密钥。
2. **频率限制**：根据B站API的限制调整频率限制器的配置，避免触发限制。
3. **HTTPS代理**：生产环境中应保持`rejectUnauthorized: true`，确保通信安全。
4. **错误处理**：增加更多的错误处理逻辑，提高系统的健壮性。


