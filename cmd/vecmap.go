package main

import (
	"vecmap/internal/database"
	"vecmap/internal/utilities"
	"vecmap/internal/utilities/logger"
)

// setLocle 按用户设备设置选定界面语言（en / zh）：
// 依次读取 LC_ALL > LC_MESSAGES > LANG，取不到时读 macOS 系统语言，
// 最后回退到英文。应用内所有文案都通过 utilities.T()/Tf() 按该语言取值。
func setLocle() utilities.Language {
	lang := utilities.InitLocale()
	log := logger.New(false)
	log.LogKey(logger.INFO, utilities.KeyLangDetected, utilities.LangName(lang))

	return lang
}

// main 是程序入口，按顺序只做三件事：
// 定语言 → 打开本地库（空路径即 ~/.vecmap/vecmap.db）→ 按该语言输出状态。
func main() {
	lang := setLocle()
	log := logger.New(false)

	if _, err := database.InitDB(""); err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyDBFailed, err)
		return
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
			return
		}
		log.LogKey(logger.INFO, utilities.KeyDBClosed)
	}()

	log.LogKey(logger.SUCCESS, utilities.KeyDBReady)
	log.LogKey(logger.INFO, utilities.KeyDBPath, database.Path())
	log.Log(logger.DEBUG, "lang=%s locale=%s", lang, utilities.Locale())
}
