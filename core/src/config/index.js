const path = require('node:path')
const configLoader = require('./local-config-loader')
const { applyRemoteConfigUrlHttps } = require('./remote-config-url')

function getRootCaCertPath () {
  return path.join(configLoader.getUserBasePath(), '/dev-sidecar.ca.crt')
}

function getRootCaKeyPath () {
  return path.join(configLoader.getUserBasePath(), '/dev-sidecar.ca.key.pem')
}

/**
 * 官方（共享）远程配置地址 —— 以「最高优先级 + 一次性覆写」的方式落到用户配置上。
 *
 * 为什么要覆写：配置合并顺序是「用户 > 个人远程 > 共享远程 > 默认」，用户配置优先级最高，
 * 所以用户本地残留的历史官方地址会盖住默认值。
 *
 * 为什么只覆写一次：只纠正 ONCE_OVERRIDE_DEPRECATED_REMOTE_CONFIG_URLS 里列出的历史官方地址。
 * 纠正之后本地址就归用户所有了 —— 用户可以在「设置」里自由改成其它地址（例如自建镜像），
 * 程序不再干预；personalUrl（个人远程配置）始终由用户掌控，且优先级更高。
 */
const HIGHEST_PRIORITY_ONCE_OVERRIDE_OFFICIAL_REMOTE_CONFIG_URL = 'https://ds-official-config.bestar.de5.net/remote_config.json5'

/** 历史官方地址：命中即被一次性纠正为 HIGHEST_PRIORITY_ONCE_OVERRIDE_OFFICIAL_REMOTE_CONFIG_URL */
const ONCE_OVERRIDE_DEPRECATED_REMOTE_CONFIG_URLS = [
  // v1.6.0 ~ v1.7.3 默认（docmirror 官方仓库 master 分支）
  'https://gitee.com/docmirror/dev-sidecar/raw/master/packages/core/src/config/remote_config.json5',
  // 更早期（2021-08 尚未定型，路径在 gui/extra 下）
  'https://gitee.com/docmirror/dev-sidecar/raw/master/packages/gui/extra/config_remote.json5',
  // v1.8.0 默认（GitHub raw）
  'https://github.com/docmirror/dev-sidecar/raw/master/packages/core/src/config/remote_config.json5',
  // v1.8.1 ~ v1.8.9、v2.0.0-RC1 默认（王良仓库 docmirror 分支）
  'https://gitee.com/wangliang181230/dev-sidecar/raw/docmirror/packages/core/src/config/remote_config.json5',
  // 开发期中间变体（2024-01 ~ 2024-04，未随 tag 发布）
  'https://gitee.com/wangliang181230/dev-sidecar/raw/master/packages/core/src/config/remote_config.json5',
  'https://gitee.com/wangliang181230/dev-sidecar/raw/master/packages/core/src/config/remote_config.json',
  'https://gitee.com/wangliang181230/dev-sidecar/raw/myself/packages/core/src/config/remote_config.json',
  'https://gitee.com/wangliang181230/dev-sidecar/raw/config/remote_config.json',
  'https://gitee.com/wangliang181230/dev-sidecar/raw/remote_config/remote_config.json',
  'https://gitee.com/wangliang181230/dev-sidecar/raw/remote_config/packages/core/src/config/remote_config.json',
  'https://gitee.com/wangliang181230/dev-sidecar/raw/docmirror/packages/core/src/config/remote_config.json',
  // v2.0.0-RC2 ~ v2.0.0.3、v2.0.1-test 默认：所属 Gitee 仓库被 Gitee 强制设为 private 后失效（见 issue #591）
  'https://gitee.com/wangliang181230/dev-sidecar/raw/docmirror2.x/packages/core/src/config/remote_config.json',
  // v2.0.1 ~ v2.0.2 默认：迁移到 dev-sidecar-config 仓库后的地址（Gitee 直链形式）
  'https://gitee.com/wangliang181230/dev-sidecar-config/raw/main/remote_config.json',
  // v2.1.0 起的地址（giteeusercontent / github raw 两种代理形式）
  'https://raw.giteeusercontent.com/wangliang181230/dev-sidecar-config/raw/main/remote_config.json',
  'https://raw.githubusercontent.com/wangliang181230/dev-sidecar-config/main/remote_config.json',
  // 第三方 fork，仅出现在 2026-04-27 一次开发提交；非官方默认，如担心覆盖用户自选镜像可删掉此条
  'https://gitee.com/wzbdyr/dev-sidecar-config/raw/main/remote_config20260426.json',
]

const defaultConfig = {
  app: {
    metaInfo: {
      // version / updateLog 由下方 SYNC:OFFICIAL-FALLBACK 区块从官方配置填充
      id: 'internal',
    },
    mode: 'default',
    autoStart: {
      enabled: false,
    },
    remoteConfig: {
      enabled: true,
      // 共享（官方）远程配置地址：默认值见 HIGHEST_PRIORITY_ONCE_OVERRIDE_OFFICIAL_REMOTE_CONFIG_URL
      url: HIGHEST_PRIORITY_ONCE_OVERRIDE_OFFICIAL_REMOTE_CONFIG_URL,
      // 个人远程配置地址
      personalUrl: '',
    },
    startShowWindow: true, // 启动时是否打开窗口：true=打开窗口, false=隐藏窗口
    needCheckHideWindow: true, // 是否需要在隐藏窗口时做检查
    showHideShortcut: 'Alt + S', // 显示/隐藏窗口快捷键
    windowSize: { width: 900, height: 750 }, // 启动时，窗口的尺寸
    theme: 'dark', // 主题：light=亮色, dark=暗色
    autoChecked: true, // 是否自动检查更新
    skipPreRelease: true, // 是否忽略预发布版本
    dock: {
      hideWhenWinClose: false,
    },
    closeStrategy: 0,
    showShutdownTip: true,
    showHomeAd: true,
    homeAd: {
      text: '',
      url: '',
      description: '',
    },

    // 日志相关配置
    logDisabled: false, // 完全禁用日志：控制台不输出，日志文件也不写入
    logDetail: false, // 详细调试日志：保留 URL path 等；仍会脱敏凭据。问题排查时再开
    migratedTo: '', // 数据迁移标记，如 '3.0.0'；空表示尚未执行对应迁移
    logFileSavePath: path.join(configLoader.getUserBasePath(), '/logs'), // 日志文件保存路径
    keepLogFileCount: 15, // 保留日志文件数
    maxLogFileSize: 1, // 最大日志文件大小
    maxLogFileSizeUnit: 'GB', // 最大日志文件大小单位
  },
  server: {
    enabled: true,
    // 绑定IP：代理端口（默认 31181）的监听地址，控制"谁能连你的代理"。
    // 0.0.0.0 = 局域网其它机器也可使用；127.0.0.1 = 仅本机。
    // 注意：MITM 假 TLS 服务器是内部件，始终绑 127.0.0.1，不受此项影响。
    host: '127.0.0.1',
    port: 31181,
    fakeServerMaxLength: 100, // fakeServer的最大缓存数量
    setting: {
      NODE_TLS_REJECT_UNAUTHORIZED: true,
      verifySsl: true,
      allowTls12: false,
      script: {
        enabled: true,
        defaultDir: './extra/scripts/',
      },
      userBasePath: configLoader.getUserBasePath(),
      rootCaFile: {
        certPath: getRootCaCertPath(),
        keyPath: getRootCaKeyPath(),
      },

      // 默认超时时间配置
      defaultTimeout: 20000, // 请求超时时间
      defaultKeepAliveTimeout: 30000, // 连接超时时间

      // 指定域名超时时间配置
      timeoutMapping: {
        'github.com': {
          timeout: 20000,
          keepAliveTimeout: 30000,
        },
      },

      // 慢速IP延迟时间：测速超过该值时，则视为延迟高，显示为橙色
      lowSpeedDelay: 200,
    },
    compatible: {
      // **** 自定义兼容配置 **** //
      // connect阶段所需的兼容性配置
      connect: {
        // 参考配置（无path）
        // 'xxx.xxx.xxx.xxx:443': {
        //   ssl: false
        // }
      },
      // request阶段所需的兼容性配置
      request: {
        // 参考配置（配置方式同 `拦截配置`）
        // 'xxx.xxx.xxx.xxx:443': {
        //   '.*': {
        //     rejectUnauthorized: false
        //   }
        // }
      },
    },
    // Cloudflare 路由重定向：命中 Cloudflare IP 段时改写为优选地址
    cloudflareRoute: {
      enabled: false,
      preferredEndpoint: '', // 优选地址，可填写 IP 或 CNAME 域名
    },
    intercept: {
      enabled: true,
    },
    // intercepts / preSetIpList / whiteList / dns 由下方 SYNC:OFFICIAL-FALLBACK 区块从官方配置填充
  },
  proxy: {},
  plugin: {},
  help: {},
}

// >>> SYNC:OFFICIAL-FALLBACK:BEGIN
// 「internal 底本」：官方配置的规则类节点，由 _script/sync-official-config.mjs 在构建时自动更新，请勿手改。
// 来源地址：https://ds-official-config.bestar.de5.net/remote_config.json5
// 来源版本：202610060150（去除自带nat64默认前缀需要用户自行查询）
// 下载失败时脚本不会改动本区块，即保留上一次的同步结果。
// 用 Object.assign 整体替换（不是深合并），这样官方「删掉」的键也会跟着消失。
/* eslint-disable no-template-curly-in-string -- 官方配置里存在 ${...} 形式的普通字符串（如代理目标），并非模板串 */
Object.assign(defaultConfig, {
  proxy: {
    excludeDomesticDomainAllowList: false,
    remoteDomesticDomainAllowListFileUrl: 'https://ghproxy.net/https://raw.githubusercontent.com/pluwen/china-domain-allowlist/main/allow-list.sorl',
    excludeIpList: {
      'objects-origin.githubusercontent.com': true,
      '*.ghproxy.net': true,
      '*.ghp.ci': true,
      '*.kkgithub.com': true,
      '*.dgithub.xyz': true,
      'pages.github.com': true,
      'help.github.com': true,
      'docs.github.com': true,
      '*.github.blog': true,
      'analytics.githubassets.com': true,
      'ghcc.githubassets.com': true,
      'www.docker.com': true,
      'login.docker.com': true,
      'api.dso.docker.com': true,
      'desktop.docker.com': true,
      'docs.docker.com': true,
      '*.live.com': null,
      '*.s-microsoft.com': true,
      '*.xboxlive.com': true,
      '*.mihoyo.com': true,
      '*.elastic.co': false,
      '*.bilicomic.com': true,
      '[2049:8c54:813:10c::140]': true,
      '[2409:8a0c:a442:ff40:a51f:4b9c:8b41:25ea]': true,
      '[2606:2800:147:120f:30c:1ba0:fc6:265a]': true,
      '*.cmicapm.com': true,
      '*.cloudflare-cn.com': true,
      '*.microsoftonline.com': true,
      '*.msedge.net': true,
      '*kaspersky*.com': true,
      '*.upd.kaspersky.com': true,
      '*.lanhuapp.com': true,
      '*.soboten.com': true,
      '*.sandboxie-plus.com': true,
      '*.wuyou.net': true,
      '*.pyecharts.org': true,
      '*.bcloudlink.com': true,
      '*.qijishow.com': true,
      '*.z-lib.fo': true,
      '*.finalshell.com': true,
      '*.minebbs.com': true,
      '*.spigotmc.org': true,
      '*.virustotal.com': true,
      '*.gitlab.com': true,
      '*.deepseek.com': true,
      '*steaminventoryhelper.com': true,
      '*.youdemai.com': true,
      '*.casualthink.com': true,
      '44.239.165.12': true,
      '3.164.110.117': true,
      'cn.*': null,
      'challenges.cloudflare.com': null,
    },
  },
  plugin: {
    overwall: {
      targets: {
        '*.github.com': true,
        '*github*.com': true,
        '*.gitbook.io': true,
        '*.nodejs.org': true,
        '*.npmjs.com': true,
        '*.wikimedia.org': true,
        '*.v2ex.com': true,
        '*.azureedge.net': true,
        '*.cloudfront.net': true,
        '*.bing.com': true,
        '*.discourse-cdn.com': true,
        '*.gravatar.com': true,
        '*.docker.com': true,
        '*.vueuse.org': true,
        '*.elastic.co': true,
        '*.optimizely.com': true,
        '*.stackpathcdn.com': true,
        '*.fastly.net': true,
        '*.cloudflare.com': true,
        '*.233v2.com': true,
        '*.v2fly.org': true,
        '*.telegram.org': true,
        '*.amazon.com': true,
        '*.googleapis.com': true,
        '*.google-analytics.com': true,
        '*.cloudflareinsights.com': true,
        '*.intlify.dev': true,
        '*.segment.io': true,
        '*.shields.io': true,
        '*.jsdelivr.net': true,
        '*.z-library.sk': true,
        '*.zlibrary*.se': true,
        '*.discord.com': true,
        '*.wikipedia-on-ipfs.org': true,
        '*.chatgpt.com': false,
        '*.oaiusercontent.com': true,
        '*.huggingface.co': true,
        '*.pixiv.org': true,
        '*.fanbox.cc': true,
        '*.onesignal.com': true,
        '*.greasyfork.org': true,
        '*.cn-greasyfork.org': true,
        '*.notepad-plus-plus.org': true,
      },
      pac: {
        pacFileUpdateUrl: 'https://xget.xi-xu.me/gh/gfwlist/gfwlist/raw/master/gfwlist.txt',
      },
    },
    free_eye: {
      Route: {
        timeout: 0.1,
        addrs: {
          IPv4: '8.8.8.8',
          IPv6: '2001:4860:4860::8888',
        },
        port: 53,
      },
      DNS: {
        timeout: 3,
        allow: [
          'baidu.cn',
          'taobao.com',
          'www.gov.cn',
        ],
        block: [
          'wikipedia.org',
          'youtube.com',
          'facebook.com',
        ],
      },
      TCP: {
        timeout: 3,
        addrs: {
          IPv4: {
            allow: [
              '114.114.114.114',
              '223.6.6.6',
            ],
            block: [
              '8.8.8.8',
              '1.1.1.1',
            ],
          },
          IPv6: {
            allow: [
              '2402:4e00::',
              '2400:3200:baba::1',
            ],
            block: [
              '2001:4860:4860::8888',
              '2606:4700:4700::1111',
            ],
          },
        },
        ports: [
          80,
          443,
        ],
      },
      TLS: {
        timeout: 3,
        addrs: {
          IPv4: '172.67.148.147',
          IPv6: '2606:4700:3036::ac43:9493',
        },
        snis: {
          allow: 'baidu.cn',
          block: 'wikipedia.org',
        },
      },
    },
  },
  help: {
    dataList: [
      {
        title: '〇、远程配置说明',
        rowClass: 'title1',
        children: [
          {
            title: '从2.0.2起，dev-sidecar原生支持显示配置元数据，不再额外手动标注。',
            rowClass: 'title2',
          },
        ],
      },
      {
        title: '一、问题处理',
        rowClass: 'title1',
        children: [
          {
            title: '1、解决Github访问不了或速度很慢的问题（切换高速IP）',
            url: 'https://github.com/docmirror/dev-sidecar/wiki/%E8%A7%A3%E5%86%B3Github%E8%AE%BF%E9%97%AE%E4%B8%8D%E4%BA%86%E6%88%96%E9%80%9F%E5%BA%A6%E5%BE%88%E6%85%A2%E7%9A%84%E9%97%AE%E9%A2%98',
          },
          {
            title: '2、Linux安装证书失败的避坑（Linux手动安装证书详细教程）',
            url: 'https://github.com/docmirror/dev-sidecar/issues/238',
          },
          {
            title: '3、解决Linux（deb）系统下无法安装根证书的问题（如何以root启动dev-sidecar）',
            url: 'https://github.com/docmirror/dev-sidecar/issues/135',
          },
          {
            title: '4、在Arch/Fedora下的证书安装',
            url: 'https://github.com/docmirror/dev-sidecar/issues/204',
          },
          {
            title: '5、在 WSL 中的使用方法（debian系Linux手动安装证书简明教程）',
            url: 'https://github.com/docmirror/dev-sidecar/issues/73',
          },
          {
            title: '6、macOS提示“dev-sidecar.app已损坏/不安全”',
            url: 'https://github.com/docmirror/dev-sidecar/issues/471',
          },
          {
            title: '> 点击前往Issue区查找更多帮助信息',
            url: 'https://github.com/docmirror/dev-sidecar/issues?q=state%3Aclosed%20label%3A%22%E5%85%B6%E4%BB%96%E7%94%A8%E6%88%B7%E5%8F%AF%E5%8F%82%E8%80%83%22',
          },
        ],
      },
      {
        title: '二、功能说明',
        rowClass: 'title1',
        children: [
          {
            title: '> 功能太多，点击前往Wiki页面查看',
            url: 'https://github.com/docmirror/dev-sidecar/wiki',
          },
        ],
      },
      {
        title: '三、DevSidecar技术交流群',
        rowClass: 'title1',
        children: [
          {
            title: 'QQ 1群：390691483，人数：500 / 500（满）',
            url: 'http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=hIG_VClE1CU2gHuLSSTaazMlo6M760iL&authKey=5VUMMwzH5FeabLDbZNZJbqmZk1gfmB%2B%2FlotO%2Brszz%2BW3E8xwKD2hTg2%2FV2LJEKL7&noverify=0&group_code=390691483',
          },
          {
            title: 'QQ 2群：667666069，人数：500 / 500（满）',
            url: 'http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=n4nksr4sji93vZtD5e8YEHRT6qbh6VyQ&authKey=XKBZnzmoiJrAFyOT4V%2BCrgX5c13ds59b84g%2FVRhXAIQd%2FlAiilsuwDRGWJct%2B570&noverify=0&group_code=667666069',
          },
          {
            title: 'QQ 3群：419807815，人数：500 / 500（满）',
            url: 'http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=zRkm0eHUhRmWWJA5O35C7BOKPZ4_gmrz&authKey=X9JHezR1BOalcEmvV6If04TN%2BIbzjAayBDaOSiuOg1SPpPguA7RqoLSHVEeo7A4e&noverify=0&group_code=419807815',
          },
          {
            title: 'QQ 4群：438148299，人数：1012 / 2000（推荐）',
            url: 'http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=i_NCBB5f_Bkm2JsEV1tLs2TkQ79UlCID&authKey=nMsVJbJ6P%2FGNO7Q6vsVUadXRKnULUURwR8zvUZJnP3IgzhHYPhYdcBCHvoOh8vYr&noverify=0&group_code=438148299',
          },
          {
            title: 'QQ 5群：767622917，人数：200 / 500',
            url: 'http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=nAWi_Rxj7mM4Unp5LMiatmUWhGimtbcB&authKey=aswmlWGjbt3GIWXtvjB2GJqqAKuv7hWjk6UBs3MTb%2Biyvr%2Fsbb1kA9CjF6sK7Hgg&noverify=0&group_code=767622917',
          },
        ],
      },
      {
        title: '四、版本更新日志和下载地址',
        rowClass: 'title1',
        url: 'https://github.com/docmirror/dev-sidecar/releases',
        children: [
          {
            title: 'v2.3.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2026-10-03 ] v2.3.0（支持 ECH 加密 SNI、请求自动重试，新增「日志与流量」「GitHub 状态监控」页）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.3.0',
              },
            ],
          },
          {
            title: 'v2.2.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2026-07-02 ] v2.2.0（实验性自动更新、HTTP/2 代理、按需 IP 探测，修复诸多安全漏洞）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.2.0',
              },
            ],
          },
          {
            title: 'v2.1.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2026-06-29 ] v2.1.1（修复 v2.1.0 中的问题及诸多安全漏洞）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.1.1',
              },
              {
                title: '[ 2026-06-28 ] v2.1.0（稳定性提升，free eye 插件回归）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.1.0',
              },
            ],
          },
          {
            title: 'v2.0.x',
            rowClass: 'title2',
            children: [
              {
                title: '待办事项',
                url: 'https://github.com/docmirror/dev-sidecar/milestone/9',
              },
              {
                title: '[ 2026-04-18 ] v2.0.2（支持IPv6、性能和稳定性提升）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.2',
              },
              {
                title: '[ 2026-04-12 ] v2.0.1（可在支持IPv6网络直连看YouTube视频了）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.1',
              },
              {
                title: '[ 2026-02-02 ] v2.0.0.3（修复脚本插入的 BUG）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0.3',
              },
              {
                title: '[ 2025-12-31 ] v2.0.1-test（测试版：从 v2.0.0.2 继承，引入 free eye 插件、修复导入 BUG；版本号故意不合规以避免触发自动更新）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.1-test',
              },
              {
                title: '[ 2025-05-15 ] v2.0.0.2',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0.2',
              },
              {
                title: '[ 2025-03-06 ] v2.0.0.1（修复了UDP类型DNS并发调用时IP赋值混乱的问题）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0.1',
              },
              {
                title: '[ 2025-03-05 ] v2.0.0',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0',
              },
              {
                title: '[ 2025-02-18 ] v2.0.0-RC6',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0-RC6',
              },
              {
                title: '[ 2025-02-07 ] v2.0.0-RC5',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0-RC5',
              },
              {
                title: '[ 2025-01-22 ] v2.0.0-RC4',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0-RC4',
              },
              {
                title: '[ 2025-01-13 ] v2.0.0-RC3（存在应用启动失败BUG，建议升级到 v2.0.0-RC4 及以上版本）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0-RC3',
              },
              {
                title: '[ 2025-01-10 ] v2.0.0-RC2',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0-RC2',
              },
              {
                title: '[ 2024-12-10 ] v2.0.0-RC1',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v2.0.0-RC1',
              },
            ],
          },
          {
            title: 'v1.8.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2024-11-07 ] v1.8.9',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.9',
              },
              {
                title: '[ 2024-10-18 ] v1.8.8（紧急修复彩蛋BUG）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.8',
              },
              {
                title: '[ 2024-10-17 ] v1.8.7（存在彩蛋BUG，建议升级到 v1.8.8 及以上版本）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.7',
              },
              {
                title: '[ 2024-09-30 ] v1.8.6（存在彩蛋BUG，建议升级到 v1.8.8 及以上版本）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.6',
              },
              {
                title: '[ 2024-09-20 ] v1.8.5（存在彩蛋BUG，建议升级到 v1.8.8 及以上版本）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.5',
              },
              {
                title: '[ 2024-09-09 ] v1.8.4',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.4',
              },
              {
                title: '[ 2024-08-27 ] v1.8.3',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.3',
              },
              {
                title: '[ 2024-07-08 ] v1.8.2',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.2',
              },
              {
                title: '[ 2024-04-28 ] v1.8.1',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.1',
              },
              {
                title: '[ 2024-04-08 ] v1.8.0',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.8.0',
              },
            ],
          },
          {
            title: 'v1.7.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2022-03-14 ] v1.7.3',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.7.3',
              },
              {
                title: '[ 2021-12-06 ] v1.7.2',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.7.2',
              },
              {
                title: '[ 2021-11-23 ] v1.7.1（升级 electron 版本，修复证书过期与 GitHub 静态资源加载问题）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.7.1',
              },
              {
                title: '[ 2021-11-21 ] v1.7.0',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.7.0',
              },
            ],
          },
          {
            title: 'v1.6.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2021-09-12 ] v1.6.2（默认配置支持远程更新，mac 顶栏图标跟随主题切换）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.6.2',
              },
              {
                title: '[ 2021-08-21 ] v1.6.1（修复 Windows 下无法开机自启的问题）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.6.1',
              },
              {
                title: '[ 2021-08-19 ] 1.6.0（支持 Ubuntu，Mac 应用名改为小写）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/1.6.0',
              },
            ],
          },
          {
            title: 'v1.5.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2021-04-05 ] v1.5.1（支持增量更新）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.5.1',
              },
              {
                title: '[ 2021-03-27 ] v1.5.0（新增模式切换与 IP 测速功能）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.5.0',
              },
            ],
          },
          {
            title: 'v1.4.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2021-01-10 ] v1.4.0（支持 mac）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.4.0',
              },
            ],
          },
          {
            title: 'v1.3.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2020-12-04 ] v1.3.1（新增 git 代理开关与增强功能）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.3.1',
              },
              {
                title: '[ 2020-12-04 ] v1.3.0（新增 git 代理开关与增强功能）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.3.0',
              },
            ],
          },
          {
            title: 'v1.2.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2020-11-29 ] v1.2.2（修复 win7 设置代理不生效、360 设置代理缓慢）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/v1.2.2',
              },
              {
                title: '[ 2020-11-19 ] 1.2.0（修复 GitHub README 引用图片打不开，新增插入脚本功能）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/1.2.0',
              },
            ],
          },
          {
            title: 'v1.1.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2020-11-14 ] 1.1.0（新增日志，修复升级后未完全退出导致的升级失败）',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/1.1.0',
              },
            ],
          },
          {
            title: 'v1.0.x',
            rowClass: 'title2',
            children: [
              {
                title: '[ 2020-11-11 ] 1.0.2',
                url: 'https://github.com/docmirror/dev-sidecar/releases/tag/1.0.2',
              },
            ],
          },
        ],
      },
    ],
  },
})
Object.assign(defaultConfig.server, {
  intercepts: {
    'github.com': {
      '.*': {
        sni: 'baidu.com',
      },
      '^(/[^/]+){2,}/?(\\?.*)?$': {
        tampermonkeyScript: 'https://ds-official-config.bestar.de5.net/tampermonkey.js',
        script: 'https://ds-official-config.bestar.de5.net/GithubEnhanced-High-Speed-Download.user.js',
        remark: '注：上面所使用的脚本地址，为高速镜像地址。',
        desc: '油猴脚本：高速下载 Git Clone/SSH、Release、Raw、Code(ZIP) 等文件 (公益加速)、项目列表单文件快捷下载、添加 git clone 命令',
      },
      '^(/[\\w-.]+){2,}/?(\\?.*)?$': null,
      '^((/[^/]+){2,})/raw((/[^/]+)+\\.(jpg|jpeg|png|gif))(\\?.*)?$': {
        proxy: null,
        sni: 'baidu.com',
        cacheDays: 365,
        desc: '仓库内图片重定向，缓存1年。',
      },
      '^((/[^/]+){2,})/raw((/[^/]+)+\\.js)(\\?.*)?$': {
        proxy: null,
        sni: 'baidu.com',
        responseReplace: {
          headers: {
            'content-type': 'application/javascript; charset=utf-8',
          },
        },
        desc: '仓库内脚本，设置响应头Content-Type。作用：方便script拦截器直接使用，避免引起跨域问题和脚本内容限制问题。',
      },
    },
    'api.github.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    'github.githubassets.com': {
      '.*': {
        sni: 'baidu.com',
      },
      '/assets/fakefile.js': {
        success: {
          script: ';',
        },
        cacheDays: 365,
      },
      '^(/[^/]+)*/[^./]+\\.(svg|png|gif|jpg|jpeg|ico|js|css)(\\?.*)?$': {
        cacheDays: 365,
        desc: '图片、JS文件、CSS文件，缓存1年',
      },
      '.*.backup': {
        desc: 'github.com域名下，该请求已经不存在，此配置暂时先备份掉。',
        proxy: 'github.com',
        sni: 'baidu.com',
        responseReplace: {
          headers: {
            'access-control-allow-origin': '*',
            'cross-origin-resource-policy': 'cross-origin',
            'set-cookie': '[remove]',
          },
        },
      },
    },
    'opengraph.githubassets.com': {
      '^/(([^/]+/){3}issues/\\d+)?(\\?.*)?$': {
        cacheDays: 365,
      },
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.githubusercontent.com': {
      '.*': {
        sni: 'baidu.com',
        requestReplace: {
          headers: {
            'accept-language': 'en-US,en;q=0.8',
          },
        },
      },
    },
    'collector.github.com': {
      '/github/collect': {
        success: true,
        status: 204,
        desc: '采集数据，快速成功',
      },
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.github.io': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.gravatar.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.windows.net': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.googleapis.com': {
      '.*': {
        sni: 'www.google.cn',
      },
    },
    'fonts.googleapis.com': {
      '.*': {
        proxy: 'fonts.googleapis.cn',
      },
    },
    'ajax.googleapis.com': {
      '.*': {
        proxy: 'ajax.proxy.ustclug.org',
        desc: '根据2026年4月24日时访问https://mirrors.ustc.edu.cn 的说明，修正internal v202604122348中指向ajax.lug.ustc.edu.cn的配置',
      },
    },
    'www.google.com': {
      '/recaptcha/.*': {
        proxy: 'www.recaptcha.net',
        desc: 'reCAPTCHA 静态资源走国内镜像，与下方 www.gstatic.com 的同源规则配套',
      },
    },
    '^(?!.*(translate-pa).google(?:apis|usercontent)?.com).*google(?:apis|usercontent)?.com$': {
      '.*': {
        sni: 'www.google.cn',
        desc: '部分需要走其它代理的服务',
      },
    },
    '^.*(youtube.com|gstatic.com|youtube.nocookie.com|youtu.be|ggpht.com|i.ytimg.com|blogger.com|doodles.google|about.google|android.com)$': {
      '.*': {
        sni: 'www.google.cn',
      },
    },
    '^.*\\.google\\.com(\\.\\w+)?$': {
      '.*': {
        sni: 'www.google.cn',
      },
    },
    '^(?<pre>.*).googlevideo.com$': {
      '.*': {
        proxy: '\${pre}.xn--ngstr-lra8j.com',
        sni: 'g.cn',
        options: true,
      },
    },
    'www.gstatic.com': {
      '/recaptcha/.*': {
        proxy: 'www.recaptcha.net',
      },
    },
    'ms-sso.copilot.microsoft.com': {
      '.*': {
        sni: 'microsoft.com',
        verifyHost: 'graph.windows.net',
      },
    },
    '*.pixiv.org': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.pximg.net': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.nikke-global.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    'i.pximg.net': {
      '.*': {
        cacheDays: 365,
        requestReplace: {
          headers: {
            referer: 'https://www.pixiv.net/',
          },
          desc: '篡改请求头\'Referer\'，使Pixiv图片链接可以单独在浏览器打开',
        },
      },
    },
    '*.youtube.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.youtu.be': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.youtube-nocookie.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    '*.ggpht.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    'i.ytimg.com': {
      '.*': {
        sni: 'baidu.com',
      },
    },
    'cdn.jsdelivr.net': {
      '^/.*\\.(js|css|png|jpg|jpeg|gif|json)(\\?.*)?$': {
        proxy: 'fastly.jsdelivr.net',
        backup: [
          'gcore.jsdelivr.net',
        ],
      },
    },
    '*.huggingface.co': {
      '.*': {
        sni: 'huggingface.cn',
        verifyHost: 'huggingface.cn',
      },
    },
    'cn.vuejs.org': {
      '.*': {
        sni: 'vuejs.org',
      },
    },
    '*steamcommunity.com': {
      '^(?!/discussions|/Profile|/app.*/discussions).*$': {
        sni: 'www.baidu.com',
        desc: '讨论区锁区,考虑不拦截丢给彩蛋',
      },
    },
    '^(?!.*cloudflare).*steamstatic.com$': {
      '.*': {
        sni: 'baidu.com',
        desc: 'steam社区数据不能也不需调整sni,直接直连',
      },
    },
    '*.steampowered.com': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
    'external-content.duckduckgo.com': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
    '*duckduckgo.com': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
    '*dropbox.com': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
    '*f-droid.org': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
    'fdroid.org': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
    '*apkmirror.com': {
      '.*': {
        sni: 'none',
      },
    },
    '*.claude.ai': {
      '.*': {
        sni: 'claude.ai',
      },
    },
    'jsd.proxy.aks.moe': {
      '^.*\\?DS_DOWNLOAD$': {
        requestReplace: {
          doDownload: true,
        },
        responseReplace: {
          doDownload: true,
        },
      },
    },
    'fastly.jsdelivr.net': {
      '^.*\\?DS_DOWNLOAD$': {
        requestReplace: {
          doDownload: true,
        },
        responseReplace: {
          doDownload: true,
        },
      },
    },
    'jsdelivr.pai233.top': {
      '^.*\\?DS_DOWNLOAD$': {
        requestReplace: {
          doDownload: true,
        },
        responseReplace: {
          doDownload: true,
        },
      },
    },
    'raw.incept.pw': {
      '^.*\\?DS_DOWNLOAD$': {
        requestReplace: {
          doDownload: true,
        },
        responseReplace: {
          doDownload: true,
        },
      },
    },
    'packages.elastic.co': {
      '.*': {
        proxy: 'elastic.proxy.ustclug.org',
      },
    },
    'ppa.launchpad.net': {
      '.*': {
        proxy: 'launchpad.proxy.ustclug.org',
      },
    },
    'downloads.openwrt.org': {
      '.*': {
        proxy: 'openwrt.proxy.ustclug.org',
      },
    },
    'registry.npmjs.org': {
      '.*': {
        desc: '既然ds有NPM镜像了，这个就没什么必要了，先不配置了',
      },
    },
    'repo1.maven.org': {
      '.*': {
        proxy: 'maven.proxy.ustclug.org',
      },
    },
    '*.instagram.com': {
      '.*': {
        sni: 'g.cn',
      },
    },
    '*.cdninstagram.com': {
      '.*': {
        sni: 'g.cn',
      },
    },
    '*.intercom.io': {
      '.*': {
        sni: 'g.cn',
      },
    },
    '*startpage.com': {
      '.*': {
        sni: 'www.baidu.com',
      },
    },
  },
  preSetIpList: {
    'github.com': {
      '20.200.245.247': true,
      '20.27.177.113': true,
      '20.205.243.166': true,
      '20.26.156.215': false,
      '20.87.245.0': false,
      '4.237.22.38': false,
      '20.201.28.151': false,
      '140.82.113.3': false,
      '140.82.114.4': false,
      '140.82.116.3': false,
      '140.82.116.4': false,
      '140.82.121.3': false,
      '140.82.121.4': false,
    },
    'gist.github.com': {
      '20.27.177.113': true,
      '20.200.245.247': true,
      '20.205.243.166': false,
      '140.82.116.3': true,
      '140.82.116.4': true,
      '4.237.22.38': true,
    },
    'github.dev': {
      '20.43.185.14': true,
      '20.99.227.183': true,
      '51.137.3.17': true,
      '52.224.38.193': true,
    },
    'github.githubassets.com': {
      '2606:50c0:8000::154': true,
      '2606:50c0:8001::154': true,
      '2606:50c0:8002::154': true,
      '2606:50c0:8003::154': true,
      '185.199.108.154': true,
      '185.199.109.154': true,
      '185.199.110.154': true,
      '185.199.111.154': true,
    },
    '*.githubusercontent.com': {
      '185.199.111.133': true,
      '185.199.108.133': true,
      '185.199.109.133': true,
      '185.199.110.133': true,
    },
    'i.pximg.net': {
      '210.140.139.132': true,
      '210.140.139.137': true,
      '203.137.29.48': true,
      '210.140.139.134': true,
      '203.137.29.49': true,
      '210.140.139.133': true,
      '210.140.139.135': true,
      '203.137.29.47': true,
    },
    'a.pixiv.org': {
      '210.140.139.182': true,
      '210.140.139.183': true,
      '210.140.139.184': true,
    },
    'api.fanbox.cc': {
      '172.64.146.116': true,
    },
    '*.fanbox.cc': {
      '210.140.139.155': true,
    },
    '^(aistudio|.*pa.clients6|apis|gemini|console.cloud|notebooklm|mail).google.com$': {
      '8.137.102.117': {
        desc: 'AI Studio相关,阿里云,解锁地区限制,新加坡,仅大陆访问',
      },
      '47.102.115.14': false,
    },
    'stitch.withgoogle.com': {
      '8.137.102.117': {
        desc: 'AI Studio相关,阿里云,解锁地区限制,新加坡,仅大陆访问',
      },
      '47.102.115.14': false,
    },
    'scholar.googleusercontent.com': {
      '142.251.190.206': true,
      '172.217.204.206': true,
      '172.253.122.206': true,
    },
    '(*account*|scholar).google.com': {
      '172.217.204.206': true,
    },
    '^(?!fonts).*(with)?google(apis|usercontent)?.com.*$': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '^(.*\\.)?usercontent\\.goog$': {
      '47.102.115.14': {
        desc: '阿里云中转,日本,实测0.45s,首选',
      },
      '8.137.102.117': {
        desc: '阿里云中转,新加坡,实测0.50s,备用',
      },
    },
    '^.*(youtube.com|gstatic.com|youtube.nocookie.com|youtu.be|ggpht.com|i.ytimg.com|blogger.com|doodles.google|about.google|android.com|antigravity.google)$': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '*.youtube.com': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '*.youtu.be': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '*.youtube-nocookie.com': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '*.ggpht.com': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    'i.ytimg.com': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '*.gstatic.com': {
      '8.137.102.117': false,
      '142.251.189.206': {
        desc: '自动地区官方',
      },
    },
    '*.huggingface.co': {
      '3.167.200.113': true,
    },
    '*.greasyfork.org': {
      '96.126.98.220': true,
      '50.116.4.196': true,
    },
    '*.cn-greasyfork.org': {
      '96.126.98.220': true,
      '50.116.4.196': true,
    },
    '*.instagram.com': {
      '163.70.159.174': true,
      '57.144.144.34': true,
      '57.144.216.34': true,
      '157.240.229.174': true,
      '57.144.188.34': true,
      '157.240.210.174': true,
      '157.240.252.174': true,
      '102.132.97.174': true,
      '31.13.94.174': true,
      '31.13.85.174': true,
      '102.132.104.174': true,
    },
    '*.cdninstagram.com': {
      '57.144.152.192': true,
      '57.144.220.192': true,
      '57.144.216.192': true,
    },
    '*z-library.sk': {
      '176.123.7.105': true,
    },
    '*z-lib.help': {
      '176.123.7.105': true,
    },
    'community.cloudflare.steamstatic.com': {
      '23.209.46.70': true,
      '104.18.42.105': true,
      '172.64.145.151': true,
    },
    'clientconfig.akamai.steamstatic.com': {
      ' 23.208.12.191': true,
      '23.32.91.19': true,
      '2.16.168.104': true,
      '2.16.168.109': true,
      '23.32.91.17': true,
      '23.208.12.174': true,
    },
    'community.steamstatic.com': {
      '146.75.47.52': true,
      '151.101.91.52': true,
      '199.232.163.52': true,
      '146.75.115.52': true,
      '199.232.215.52': true,
      '199.232.211.52': true,
      '151.101.79.52': true,
    },
    'cdn.steamcommunity.com': {
      '23.221.227.5': true,
    },
    '*.steamcommunity.com': {
      '23.209.217.19': true,
      '23.15.140.216': true,
      '104.79.200.218': true,
    },
    '^(store|checkout).steampowered.com$': {
      '23.209.218.108': true,
      '184.31.230.122': true,
      '23.35.102.114': true,
      '104.83.198.104': true,
      '23.51.62.114': true,
      '23.55.98.103': true,
    },
    '*x.com': {
      '172.67.172.22': true,
    },
    '*twimg.com': {
      '172.67.172.22': true,
    },
    '*twitter.com': {
      '172.67.172.22': true,
    },
    '*t.co': {
      '172.67.172.22': true,
    },
    'external-content.duckduckgo.com': {
      '20.43.160.189': true,
    },
    '*duckduckgo.com': {
      '20.43.161.105': true,
    },
    '*onedrive.live.com': {
      '13.107.42.13': true,
    },
    '*dropbox.com': {
      '162.125.248.18': true,
    },
    'forum.f-droid.org': {
      '37.218.242.53': true,
    },
    '*f-droid.org': {
      '37.218.243.72': true,
    },
    'fdroid.org': {
      '37.218.243.72': true,
    },
    '*apkmirror.com': {
      '104.17.67.215': true,
    },
    '*startpage.com': {
      '67.63.58.139': true,
    },
    '*.claude.ai': {
      '2a01:4f8:c2c:123f:64:5:a04f:680a': true,
    },
    'cdn.jsdelivr.net': {
      '104.16.89.20': true,
    },
  },
  whiteList: {
    '*.icloud.com': true,
    '*.lenovo.net': true,
    'localhost': true,
    '127.*.*.*': true,
    '192.168.*.*': true,
    'cn.*': null,
    '192.168.*': null,
  },
  dns: {
    providers: {
      'local': {
        server: '127.0.0.1',
      },
      'aliyun': {
        server: '223.5.5.5',
      },
      'safe360': {
        server: 'tls://dot.360.cn',
        forSNI: true,
      },
      'cf-DoT': {
        server: 'tls://1.1.1.1',
        sni: 'baidu.com',
      },
      'bebasid': {
        server: 'tls://dns.bebasid.com',
        sni: 'baidu.com',
      },
      'cf-DoH': {
        server: 'https://cloudflare-dns.com/dns-query',
        sni: 'baidu.com',
      },
      'quad9-ip': {
        server: 'https://9.9.9.9/dns-query',
      },
      'cf-ip': {
        server: 'https://1.1.1.1/dns-query',
      },
      'rubyfish': {
        server: 'https://rubyfish.cn/dns-query',
      },
    },
    mapping: {
      '*.xn--ngstr-lra8j.com': 'bebasid',
      '*.googlevideo.com': 'bebasid',
      '*.gvt1.com': 'bebasid',
      '*.jetbrains.com': 'cf-DoT',
      '*.azureedge.net': 'cf-DoT',
      '*.stackoverflow.com': 'cf-DoT',
      '*.github.io': 'cf-DoT',
      '*.electronjs.org': 'cf-DoT',
      '*.amazonaws.com': 'cf-DoT',
      '*.yarnpkg.com': 'cf-DoT',
      '*.cloudfront.net': 'cf-DoT',
      '*.cloudflare.com': 'cf-DoT',
      'img.shields.io': 'cf-DoT',
      '*.vuepress.vuejs.org': 'cf-DoT',
      '*.gh.docmirror.top': 'cf-DoT',
      '*.v2ex.com': 'cf-DoT',
      '*.pypi.org': 'cf-DoT',
      '*.pixiv.org': 'cf-DoT',
      '*.pximg.net': 'cf-DoT',
      '*.onesignal.com': 'cf-DoT',
      '*.iubenda.com': 'cf-DoT',
      '*.brave.com': 'cf-DoT',
    },
    familyMapping: {
      '*.xn--ngstr-lra8j.com': '6',
      '*.googlevideo.com': '6',
      '*.gvt1.com': '6',
      '*.jetbrains.com': '4',
      '*.azureedge.net': '4',
      '*.stackoverflow.com': '4',
      '*.github.com': '4',
      '*github*.com': '4',
      '*.github.io': '4',
      '*.docker.com': '4',
      '*.electronjs.org': '4',
      '*.amazonaws.com': '4',
      '*.yarnpkg.com': '4',
      '*.cloudfront.net': '4',
      '*.cloudflare.com': '4',
      'img.shields.io': '4',
      '*.vuepress.vuejs.org': '4',
      '*.gh.docmirror.top': '4',
      '*.v2ex.com': '4',
      '*.pypi.org': '4',
      '*.pixiv.org': '4',
      '*.pximg.net': '4',
      '*.onesignal.com': '4',
      '*.iubenda.com': '4',
      '*.brave.com': '4',
      '*duckduckgo.com': '4',
      '*.gstatic.com': '4',
      '*.googleapis.com': '4',
    },
    speedTest: {
      enabled: true,
      interval: 60000,
      hostnameList: [
        'google.com',
        'github.com',
      ],
      dnsProviders: [
        'cf-DoT',
        'safe360',
      ],
    },
    ech: {
      domains: [
        '*t.co',
        '*twitter.com',
        '*twimg.com',
        '*sci-hub.pub',
        '*x.com',
        '*docker.com',
        '*pixiv.net',
        '*chatgpt.com',
        '*civitai.com',
        '*ldstatic.com',
        'civitai.com',
        '*linux.do',
        '*greasyfork.org',
      ],
      preSetIpDomains: [
        '*ldstatic.com',
        '*t.co',
        '*twitter.com',
        '*twimg.com',
        '*x.com',
      ],
      dns: 'cf-DoH',
      enabled: true,
      use: true,
      publicName: 'cloudflare-ech.com',
      cacheSize: 512,
      emptyTtl: 600000,
      minTtl: 60000,
      maxTtl: 3600000,
      tryAllProviders: true,
      parallelDelay: 200,
    },
    nat64: {
      enabled: true,
      prefix: '',
      domains: [
        '*chatgpt.com',
      ],
      dns: 'cf-DoH',
    },
  },
})
Object.assign(defaultConfig.app.metaInfo, {
  version: 202610060150,
  updateLog: '去除自带nat64默认前缀需要用户自行查询',
})
/* eslint-enable no-template-curly-in-string */
// <<< SYNC:OFFICIAL-FALLBACK:END

/**
 * 修正合并后的远程配置地址：
 * 1. 命中 ONCE_OVERRIDE_DEPRECATED_REMOTE_CONFIG_URLS 的历史官方地址 → 一次性纠正为官方地址；
 * 2. 裸 HTTP 地址 → 改写为 HTTPS（远程配置已不支持裸HTTP，见 ./remote-config-url.js）。
 *
 * 注意：只修正内存中的合并结果，持久化写回由 config-api.js 的 persistRemoteConfigUrlHttps 负责。
 *
 * @param {object} config 合并后的配置
 * @returns {object} 原 config（就地修改）
 */
function applyRemoteConfigUrlFix (config) {
  const remoteConfig = config?.app?.remoteConfig
  if (remoteConfig == null) {
    return config
  }

  if (ONCE_OVERRIDE_DEPRECATED_REMOTE_CONFIG_URLS.includes(remoteConfig.url)) {
    remoteConfig.url = HIGHEST_PRIORITY_ONCE_OVERRIDE_OFFICIAL_REMOTE_CONFIG_URL
  }

  return applyRemoteConfigUrlHttps(config)
}

// 从本地文件中加载配置。此启动快照仅供模块初始化期消费者使用，不属于默认配置。
const configFromFiles = applyRemoteConfigUrlFix(
  configLoader.getConfigFromFiles(configLoader.getUserConfig(), defaultConfig),
)

module.exports = { defaultConfig, configFromFiles, applyRemoteConfigUrlFix }
