package main // 程序入口包

import ( // 导入标准库与第三方库
	"crypto/tls" // TLS 配置与常量
	"flag" // 标准 flag 库（与 pflag 结合使用）
	"fmt" // 字符串格式化
	"io" // I/O 原语（Reader/Writer/ReadAll）
	"log" // 标准日志（用于辅助，主要用自定义 Logger）
	"net/http" // HTTP 服务器与处理器
	"os" // 操作系统接口（文件/环境/退出）
	"strings" // 字符串处理

	pflag "github.com/spf13/pflag" // 命令行解析库，支持 GNU 风格参数
	"gopkg.in/yaml.v3" // YAML 编解码库
)

const defaultConfigPath = "/etc/webhook.conf" // 默认配置文件路径

// LogLevel represents allowed log levels. // 日志级别类型定义
type LogLevel int // 使用整型枚举表达日志级别

const ( // 日志级别枚举常量（从低到高）
	LogDebug LogLevel = iota // 调试级别，最详细
	LogInfo                  // 信息级别
	LogWarn                  // 警告级别
	LogError                 // 错误级别
	LogFatal                 // 致命级别，输出后退出
)

func parseLogLevel(s string) (LogLevel, error) { // 解析字符串为日志级别
	s = strings.ToLower(strings.TrimSpace(s)) // 统一为小写并去除空白
	switch s { // 匹配不同级别字符串
	case "debug":
		return LogDebug, nil // 返回 Debug
	case "info":
		return LogInfo, nil // 返回 Info
	case "warn", "warning":
		return LogWarn, nil // 返回 Warn
	case "error":
		return LogError, nil // 返回 Error
	case "fatal":
		return LogFatal, nil // 返回 Fatal
	default:
		return LogInfo, fmt.Errorf("invalid log level: %s (allowed: debug, info, warn, error, fatal)", s) // 非法级别报错
	}
}

// Logger is a minimal leveled logger wrapper. // 轻量级分级日志器
type Logger struct { // 日志器结构体
	minLevel LogLevel // 最低输出级别
	l        *log.Logger // 包装标准库 log.Logger
}

func newLogger(min LogLevel, out io.Writer) *Logger { // 创建 Logger，指定最小级别与输出
	return &Logger{minLevel: min, l: log.New(out, "", log.LstdFlags)} // 使用标准时间前缀
}

func (lg *Logger) enabled(level LogLevel) bool { return level >= lg.minLevel } // 判断是否应输出该级别日志

func (lg *Logger) Debugf(format string, v ...any) { if lg.enabled(LogDebug) { lg.l.Printf("[DEBUG] "+format, v...) } } // Debug 日志
func (lg *Logger) Infof(format string, v ...any)  { if lg.enabled(LogInfo) { lg.l.Printf("[INFO] "+format, v...) } }  // Info 日志
func (lg *Logger) Warnf(format string, v ...any)  { if lg.enabled(LogWarn) { lg.l.Printf("[WARN] "+format, v...) } }  // Warn 日志
func (lg *Logger) Errorf(format string, v ...any) { if lg.enabled(LogError) { lg.l.Printf("[ERROR] "+format, v...) } } // Error 日志
func (lg *Logger) Fatalf(format string, v ...any) { lg.l.Printf("[FATAL] "+format, v...); os.Exit(1) } // Fatal 日志并退出

// Config represents the YAML config structure. // 配置文件映射结构体
type Config struct { // YAML 字段与结构体字段的映射
	ListenAddr   string `yaml:"listen_addr"`   // 监听地址，例如 0.0.0.0
	Port        int    `yaml:"port"`          // 端口，例如 8080
	EnableHTTPS bool   `yaml:"https"`         // 是否开启 HTTPS
	CertFile    string `yaml:"cert_file"`     // TLS 证书文件路径
	KeyFile     string `yaml:"key_file"`      // TLS 私钥文件路径
	Path        string `yaml:"path"`          // Webhook 路径，例如 /webhook
	LogLevel    string `yaml:"log_level"`     // 日志级别：debug/info/warn/error/fatal
	LogFile     string `yaml:"log_file"`      // 日志输出：文件路径、journalctl 或 -（stderr）
}

func loadConfig(path string) (*Config, error) { // 从路径加载 YAML 配置
	file, err := os.Open(path) // 打开配置文件
	if err != nil { // 打开失败
		return nil, fmt.Errorf("open config: %w", err) // 返回错误
	}
	defer file.Close() // 确保函数结束时关闭文件

	var cfg Config // 创建配置对象
	dec := yaml.NewDecoder(file) // 新建 YAML 解码器
	if err := dec.Decode(&cfg); err != nil { // 解码文件内容到 cfg
		return nil, fmt.Errorf("decode yaml: %w", err) // 解码失败返回错误
	}

	// Defaults // 设置默认值
	if cfg.ListenAddr == "" { // 未配置监听地址
		cfg.ListenAddr = "0.0.0.0" // 默认监听所有地址
	}
	if cfg.Port == 0 { // 未配置端口
		cfg.Port = 8080 // 默认端口 8080
	}
	if cfg.Path == "" { // 未配置路径
		cfg.Path = "/webhook" // 默认路径 /webhook
	}
	if strings.TrimSpace(cfg.LogLevel) == "" { // 未配置日志级别
		cfg.LogLevel = "info" // 默认 info
	}
	if strings.TrimSpace(cfg.LogFile) == "" { // 未配置日志输出
		// Default to "journalctl" which maps to stderr; journald captures stdout/err on Linux // 注：journalctl 表示输出到 stderr，由 systemd 捕获
		cfg.LogFile = "journalctl" // 默认 journalctl
	}

	return &cfg, nil // 返回配置对象
}

func resolveLogger(cfg *Config, flagLevel, flagFile string) *Logger { // 基于配置与命令行旗标生成 Logger
	// Merge: flags override config if provided // 合并策略：命令行参数优先
	levelStr := cfg.LogLevel // 初始取配置的级别
	fileStr := cfg.LogFile // 初始取配置的文件
	if strings.TrimSpace(flagLevel) != "" { // 若命令行提供了级别
		levelStr = flagLevel // 覆盖
	}
	if strings.TrimSpace(flagFile) != "" { // 若命令行提供了文件
		fileStr = flagFile // 覆盖
	}

	lvl, err := parseLogLevel(levelStr) // 解析日志级别
	if err != nil { // 解析失败
		// Fall back to info if invalid, but report to stderr // 回退到 info，并报告错误
		fmt.Fprintf(os.Stderr, "invalid log level %q: %v; defaulting to info\n", levelStr, err) // 打印错误提示
		lvl = LogInfo // 使用 Info
	}

	var out io.Writer = os.Stderr // 默认输出到标准错误
	// Treat "journalctl" (default) and "-" as stderr // "journalctl" 或 "-" 都表示使用 stderr
	if strings.TrimSpace(strings.ToLower(fileStr)) != "journalctl" && strings.TrimSpace(fileStr) != "-" { // 若配置为文件路径
		f, err := os.OpenFile(fileStr, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644) // 追加写方式打开/创建
		if err != nil { // 打开失败
			fmt.Fprintf(os.Stderr, "failed to open log file %q: %v; using stderr\n", fileStr, err) // 告警并回退 stderr
		} else {
			out = f // 使用文件作为输出
		}
	}

	return newLogger(lvl, out) // 返回 Logger
}

func main() { // 程序入口
	// Support -f and --config.file, plus logging flags // 支持 -f 与 --config.file，以及日志相关参数
	var ( // 定义命令行变量
		shortConfig string // -f/--config 的值（别名）
		longConfig  string // --config.file 的值
		flagLogLevel string // --log.level 的值
		flagLogFile  string // --log.file 的值
	)

	// Use standard flag set to keep compatibility with environments expecting it // 使用标准 flag 集，兼容部分环境
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError) // 新建 flag 集，出错不退出
	flag.CommandLine.SetOutput(io.Discard) // 将标准 flag 的默认输出丢弃（由 pflag 管理）

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine) // 将标准 flag 集合并入 pflag
	pflag.StringVarP(&shortConfig, "config", "f", "", "Path to config file (alias for --config.file)") // 定义 -f/--config
	pflag.StringVar(&longConfig, "config.file", "", "Path to config file (default /etc/webhook.conf)") // 定义 --config.file
	pflag.StringVar(&flagLogLevel, "log.level", "", "Log level: debug, info, warn, error, fatal") // 定义 --log.level
	pflag.StringVar(&flagLogFile, "log.file", "", "Log output file path; default 'journalctl' (stderr for journald)") // 定义 --log.file
	if err := pflag.CommandLine.Parse(os.Args[1:]); err != nil { // 解析命令行
		log.Fatalf("parse flags: %v", err) // 解析失败直接退出
	}

	configPath := firstNonEmpty(longConfig, shortConfig, defaultConfigPath) // 决定配置文件路径（命令行优先，默认 /etc/webhook.conf）

	cfg, err := loadConfig(configPath) // 加载配置文件
	if err != nil { // 加载失败
		log.Fatalf("failed to load config from %s: %v", configPath, err) // 打印并退出
	}

	logger := resolveLogger(cfg, flagLogLevel, flagLogFile) // 构建 Logger（合并命令行与配置）

	mux := http.NewServeMux() // 新建 HTTP 路由多路复用器
	mux.HandleFunc(cfg.Path, func(w http.ResponseWriter, r *http.Request) { // 注册 Webhook 处理函数至配置路径
		// Read body (limit size to avoid abuse) // 读取请求体并限制最大 10MB
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20)) // 10MB cap // 读取完整请求体
		_ = r.Body.Close() // 关闭请求体

		// Log request details // 打印请求详情
		HeadersStr := "None"
		var headers []string
		if len(r.Header) > 0 {
			HeadersStr = string()
		}
		// for name, values := range r.Header {
		// 	headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ", ")))
		// }
		// headersStr := strings.Join(headers, "; ")

		bodyStr := "None"
		if len(body) > 0 {
			bodyStr = string(body)
		}

		logger.Infof("%s %s from %s  Headers: [%s]  Body: %s", r.Method, r.URL.Path, r.RemoteAddr, headersStr, bodyStr)

		w.WriteHeader(http.StatusOK) // 返回 200 状态码
		_, _ = w.Write([]byte("ok")) // 返回简单内容
	})

	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.Port) // 组合监听地址
	server := &http.Server{ // 创建 HTTP 服务器
		Addr:    addr, // 监听地址:端口
		Handler: mux, // 请求处理器
	}

	logger.Infof("Starting webhook server on %s path=%s https=%v", addr, cfg.Path, cfg.EnableHTTPS) // 启动信息
	if cfg.EnableHTTPS { // 如果启用 HTTPS
		// Validate certs exist // 验证证书与私钥存在
		if cfg.CertFile == "" || cfg.KeyFile == "" { // 缺少证书或私钥
			logger.Fatalf("https enabled but cert_file or key_file not provided") // 退出并提示
		}
		if _, err := os.Stat(cfg.CertFile); err != nil { // 检查证书文件
			logger.Fatalf("cert file: %v", err) // 不存在或无权访问则退出
		}
		if _, err := os.Stat(cfg.KeyFile); err != nil { // 检查私钥文件
			logger.Fatalf("key file: %v", err) // 不存在或无权访问则退出
		}

		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12} // 设置 TLS 最低版本 1.2
		if err := server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil && err != http.ErrServerClosed { // 启动 HTTPS 服务
			logger.Fatalf("server error: %v", err) // 运行错误则退出
		}
		return // HTTPS 情况下已返回
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed { // 启动 HTTP 服务
		logger.Fatalf("server error: %v", err) // 运行错误则退出
	}
}

func firstNonEmpty(values ...string) string { // 返回第一个非空白字符串
	for _, v := range values { // 遍历候选值
		if strings.TrimSpace(v) != "" { // 若非空白
			return v // 返回该值
		}
	}
	return "" // 若都为空，返回空字符串
}