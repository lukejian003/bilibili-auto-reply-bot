require('dotenv').config();
const axios = require('axios');
const crypto = require('crypto');
const https = require('https');
const axiosRetry = require('axios-retry').default
const { RateLimiterMemory } = require('rate-limiter-flexible');

// 环境变量配置（.env文件需配置）
const {
  WX_APPID,
  WX_APPSECRET,
  ENCODING_AES_KEY,
  WX_API_BASE_URL,
  CACHE_EXPIRY,
  B_API_BASE_URL,
  B_COOKIES
} = process.env;


// 公共配置
const axiosInstance = axios.create({
  baseURL: WX_API_BASE_URL,
  timeout: 10000,
  httpsAgent: new https.Agent({
    rejectUnauthorized: true // 生产环境应保持true
  })
});

// 添加请求重试逻辑
axiosRetry(axiosInstance, {
  retries: 3,
  retryCondition: (error) => {
    return error.response?.status >= 500;
  }
});

// Token缓存管理
const tokenCache = {
  value: null,
  expiry: 0
};

// 频率限制器（每分钟最多30次请求）
const rateLimiter = new RateLimiterMemory({
  points: 30,
  duration: 60,
  blockDuration: 60
});

// 公共参数生成函数
const generateCommonParams = () => ({
  timestamp: Math.floor(Date.now() / 1000),
  nonce: crypto.randomBytes(16).toString('hex').slice(0, 10),
  requestId: crypto.randomUUID()
});

// 签名生成函数
const generateSignature = (appSecret, timestamp, nonce, bodyMd5) => {
  const signStr = `${appSecret}${timestamp}${nonce}${bodyMd5}`;
  return crypto.createHash('md5').update(signStr).digest('hex');
};


function pkcs5UnPadding(text) {
  let pad = text[text.length - 1];
  if (pad < 1 || pad > 32) {
    pad = 0;
  }
  return text.slice(0, text.length - pad);
};

function pkcs5Padding(text) {
  const blockSize = 32;
  const textLength = text.length;
  const amountToPad = blockSize - (textLength % blockSize);

  const result = Buffer.alloc(amountToPad);
  result.fill(amountToPad);

  return Buffer.concat([text, result]);
};

// 解密
function decrypt(text) {
  const { AESKey, iv } = getAESKey();
  const decipher = crypto.createDecipheriv('aes-256-cbc', AESKey, iv);
  decipher.setAutoPadding(false);
  const deciphered = Buffer.concat([decipher.update(text, 'base64'), decipher.final()]);
  return pkcs5UnPadding(deciphered).toString();
}
// 加密
function encrypt(text) {
  const { AESKey, iv } = getAESKey();
  const msg = Buffer.from(text);
  const encoded = pkcs5Padding(msg);
  var cipher = crypto.createCipheriv('aes-256-cbc', AESKey, iv);
  cipher.setAutoPadding(false);
  var cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);
  return cipheredMsg.toString('base64');
}

// 
function getAESKey() {
  const encodingAESKey = ENCODING_AES_KEY;
  const AESKey = Buffer.from(encodingAESKey + '=', 'base64');
  if (AESKey.length !== 32) {
    throw new Error('encodingAESKey invalid');
  }
  return {
    AESKey,
    iv: AESKey.slice(0, 16)
  }
}
/**
 * 获取有效Token（带缓存和自动刷新）
 * @returns {Promise<string>}
 */
async function getValidToken() {
  const now = Date.now();

  // 检查缓存是否有效
  if (tokenCache.value && tokenCache.expiry > now) {
    return tokenCache.value;
  }

  // 使用频率限制器控制请求速率
  await rateLimiter.consume(1);

  try {
    const { timestamp, nonce, requestId } = generateCommonParams();
    const bodyMd5 = crypto.createHash('md5').update('{}').digest('hex');
    const sign = generateSignature(WX_APPSECRET, timestamp, nonce, bodyMd5);

    const response = await axiosInstance.post(
      '/v2/token',
      {},
      {
        headers: {
          'X-APPID': WX_APPID,
          'request_id': requestId,
          'timestamp': timestamp,
          'nonce': nonce,
          'sign': sign,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.code === 0) {
      const newToken = response.data.data.access_token;
      tokenCache.value = newToken;
      tokenCache.expiry = now + (CACHE_EXPIRY - 5000);
      return newToken;
    }
    throw new Error(`获取Token失败: ${response.data.msg || '未知错误'}`);
  } catch (error) {
    tokenCache.value = null;
    throw new Error(`Token获取失败: ${error.response?.data?.msg || error.message}`);
  }
}
/**
 * query: '', //	用户发送的消息 
 * env: '', //	默认是 online, debug 是测试环境, online 是线上环境
 * first_priority_skills: [], //	限定技能命中范围 比如：["技能 1"]，只匹配命中“技能 1”中的所有问答内容
 * second_priority_skills: [], //	限定技能命中范围 比如：["技能 2"]，只匹配命中“技能 2”中的所有问答内容,比 first_priority_skills 命中优先级低 
 * user_name: '', //	用户昵称 
 * avatar: '', //	用户头像 
 * userid: '', //	用户 ID(可以是任何值  
 */
async function bot(data) {
  const params = {
    env: 'online', //	默认是 online, debug 是测试环境, online 是线上环境
    first_priority_skills: [], //	限定技能命中范围 比如：["技能 1"]，只匹配命中“技能 1”中的所有问答内容
    second_priority_skills: [], //	限定技能命中范围 比如：["技能 2"]，只匹配命中“技能 2”中的所有问答内容,比 first_priority_skills 命中优先级低  
    ...data
  }
  try {
    const accessToken = await getValidToken();
    const encryptStr = encrypt(JSON.stringify(params))
    const { timestamp, nonce, requestId } = generateCommonParams();
    const bodyMd5 = crypto.createHash('md5').update(encryptStr).digest('hex');
    const sign = generateSignature(WX_APPSECRET, timestamp, nonce, bodyMd5);
    const response = await axiosInstance.post(
      '/v2/bot/query',
      encryptStr,
      {
        headers: {
          'X-OPENAI-TOKEN': accessToken,
          'X-APPID': WX_APPID,
          'request_id': requestId,
          'timestamp': timestamp,
          'nonce': nonce,
          'sign': sign,
          'Content-Type': 'text/plain'
        }
      }
    );
    const res = JSON.parse((decrypt(response.data)))
    if (res.code === 0) {
      console.log(res.data);
      let contentStr = res.data.intent_name + '\n' + res.data.answer
      if (res.data.options) {
        res.data.options.forEach(item => {
          contentStr = contentStr + '\n' + item.title + '\n' + item.answer
        })
      }
      sendMsg(params.userid, contentStr)
    }
  } catch (error) {
    poller.stop();
    throw new Error(`报错信息: ${error.response?.data?.msg || error.message}`);
  }
}


class Poller {
  constructor(callback, interval = 30000) {
    this.interval = interval;
    this.callback = callback;
    this.timer = null;
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) return;

    this.timer = setInterval(async () => {
      try {
        await this.callback();
      } catch (error) {
        console.error('Polling error:', error.message);
        this.stop(); // 发生错误时自动停止
      }
    }, this.interval);

    this.isRunning = true;
    return this;
  }

  stop() {
    if (!this.isRunning) return;

    clearInterval(this.timer);
    this.isRunning = false;
    return this;
  }
}


// 公共配置
const axiosBilbil = axios.create({
  baseURL: B_API_BASE_URL,
  timeout: 10000,
  httpsAgent: new https.Agent({
    rejectUnauthorized: true // 生产环境应保持true
  })
});

// 添加请求重试逻辑
axiosRetry(axiosBilbil, {
  retries: 3,
  retryCondition: (error) => {
    return error.response?.status >= 500;
  }
});

// 公共配置
const axiosBilbilLive = axios.create({
  baseURL: 'https://api.live.bilibili.com',
  timeout: 10000,
  httpsAgent: new https.Agent({
    rejectUnauthorized: true // 生产环境应保持true
  })
});

// 添加请求重试逻辑
axiosRetry(axiosBilbilLive, {
  retries: 3,
  retryCondition: (error) => {
    return error.response?.status >= 500;
  }
});

// 公共配置
const axiosBilbilOther = axios.create({
  baseURL: 'https://api.bilibili.com',
  timeout: 10000,
  httpsAgent: new https.Agent({
    rejectUnauthorized: true // 生产环境应保持true
  })
});

// 添加请求重试逻辑
axiosRetry(axiosBilbilOther, {
  retries: 3,
  retryCondition: (error) => {
    return error.response?.status >= 500;
  }
});


// 获取未读私信
async function getUnreadPrivateMessage() {
  try {
    const response = await axiosBilbil.get(
      '/session_svr/v1/session_svr/single_unread',
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'cookie': B_COOKIES
        }
      }
    );
    const res = response.data
    if (res.code === 0) {
      console.log('未读私信', res.data);
      // res.data.unfollow_unread 未读信息的数量
      if (res.data.unfollow_unread + res.data.follow_unread > 0) {
        getUnreadDetails()
        // console.log(res.data.unfollow_unread);
      }
    }
  } catch (error) {
    throw new Error(`报错信息: ${error.response?.data?.msg || error.message}`);
  }
}

// 使用示例
const poller = new Poller(async () => {
  console.log('定时器:', new Date().toISOString());
  // 添加你的业务逻辑
  getUnreadPrivateMessage()
}, 30000);



let myInfo = {
  mid: '',
  uname: '',
  userid: '',
  sign: '',
  birthday: '',
  sex: '',
  nick_free: '',
  rank: ''
} // up主的信息

// 获取我的信息
async function getMyInfo() {
  try {
    const response = await axiosBilbilOther.get(
      '/x/member/web/account',
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'cookie': B_COOKIES
        }
      }
    );
    const res = response.data
    if (res.code === 0) {
      console.log('我的信息', res.data)
      myInfo = res.data
      poller.start();
    } else {
      console.log('我的信息报错', JSON.stringify(res));
    }
  } catch (error) {
    console.log('error', error);
    poller.stop();
    throw new Error(`报错信息: ${error.response?.data?.msg || error.message}`);
  }
}


// 获取未读私信详情
async function getUnreadDetails() {
  const { timestamp } = generateCommonParams();
  try {
    const response = await axiosBilbil.get(
      `/session_svr/v1/session_svr/new_sessions?begin_ts=${timestamp}&build=0&mobi_app=web`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'cookie': B_COOKIES
        }
      }
    );
    const res = response.data
    if (res.code === 0) {
      /**
       * unread_count 未读消息数量 
       * system_msg_type 消息类型 0 用户发送的消息
       * session_type 1 私聊
       * last_msg.msg_type 1 非系统消息
       *  **/
      const unReadSessionList = res.data.session_list.filter(item => !item.account_info && item.last_msg && item.last_msg.msg_type === 1 && item.session_type === 1 && item.system_msg_type === 0 && item.unread_count > 0)
      unReadSessionList.forEach(item => {
        getMsgContent(item)
      })
      // console.log('🚀 ~ getUnreadDetails ~ unReadSessionList:', unReadSessionList)
      // console.log(res.data.session_list);
    }
  } catch (error) {
    poller.stop();
    throw new Error(`报错信息: ${error.response?.data?.msg || error.message}`);
  }
}

// 获取私信内容
async function getMsgContent(data) {
  try {
    let user_name = '未知用户'
    let avatar = ''
    // 通过直播站API获取用户信息（无鉴权）
    const userInfoRes = await axiosBilbilLive.get(
      `/live_user/v1/Master/info?uid=${data.talker_id}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
      }
    );
    if (userInfoRes.data.code === 0) {
      user_name = userInfoRes.data.data.info.uname
      avatar = userInfoRes.data.data.info.face
    }
    // 获取私信内容
    const response = await axiosBilbil.get(
      `/svr_sync/v1/svr_sync/fetch_session_msgs?talker_id=${data.talker_id}&session_type=1&size=${data.unread_count}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'cookie': B_COOKIES
        }
      }
    );
    const res = response.data
    if (res.code === 0) {
      res.data.messages.forEach(item => {
        if (item.content) {
          const { content } = JSON.parse(item.content)
          const params = {
            query: content, //	用户发送的消息 
            user_name: user_name, //	用户昵称 
            avatar: avatar, //	用户头像 
            userid: data.talker_id, //	用户 ID(可以是任何值  
          }
          bot(params)
        }
      })
    }
  } catch (error) {
    poller.stop();
    throw new Error(`报错信息: ${error.response?.data?.msg || error.message}`);
  }
}

// 获取 CSRF
function getCSRF() {
  // 从 document.cookie 中提取所有 Cookie
  const cookies = B_COOKIES.split('; ');

  // 遍历 Cookie 查找 bili_csrf 或 bili_jct（B站两种可能的 CSRF 存储位置）
  for (const cookie of cookies) {
    const [key, value] = cookie.split('=');
    if (key === 'bili_csrf') {
      return decodeURIComponent(value); // 找到 bili_csrf 直接返回
    } else if (key === 'bili_jct') {
      return decodeURIComponent(value); // 若无 bili_csrf，返回 bili_jct 作为备用
    }
  }

  return null; // 未找到 CSRF 令牌
}

// 发送私信
async function sendMsg(receiverId, answer) {
  console.log(receiverId);
  try {
    const { timestamp, nonce, requestId } = generateCommonParams();
    const UUID = crypto.randomUUID()
    // const senderUid = ''; // 发送者mid
    // const receiverId = ''; // 接收者mid
    const receiverType = 1; // 接收者类型：用户
    const msgType = 1; // 消息类型：文字
    const content = { content: answer }; // 消息内容
    const csrfToken = getCSRF()
    const csrf = getCSRF()
    // 构造请求参数
    const params = {
      'msg[sender_uid]': myInfo.mid,
      'msg[receiver_id]': receiverId,
      'msg[receiver_type]': receiverType,
      'msg[msg_type]': msgType,
      'msg[msg_status]': 0,
      'msg[dev_id]': UUID,
      'msg[timestamp]': timestamp,
      'msg[new_face_version]': 1, // 使用新版表情包
      'msg[content]': JSON.stringify(content),
      'csrf_token': csrfToken,
      'csrf': csrf,
      'build': 0,
      'mobi_app': 'web'
    }
    console.log(params);
    const response = await axiosBilbil.post(
      `/web_im/v1/web_im/send_msg`,
      params,
      {
        headers: {
          // 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
          // 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Content-Type': 'application/x-www-form-urlencoded',
          'cookie': B_COOKIES
        },
        transformRequest: [(data, headers) => {
          // 将请求参数转换为application/x-www-form-urlencoded格式
          let paramsArray = [];
          for (let key in data) {
            if (data.hasOwnProperty(key)) {
              paramsArray.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
            }
          }
          return paramsArray.join('&');
        }]
      },
    );
    const res = response.data
    if (res.code === 0) {
      console.log(res)
    } else {
      console.log('接口报错信息：' + JSON.stringify(res))
    }
  } catch (error) {
    poller.stop();
    throw new Error(`报错信息: ${error.response?.data?.msg || error.message}`);
  }
}




// 使用示例
(async () => {
  try {
    // const accessToken = await getValidToken();
    // console.log('Access Token:', accessToken);
    // bot(params)
    // getUnreadPrivateMessage()
    getMyInfo()
  } catch (error) {
    console.error('获取Access Token失败:', error.message);
  }
})();
