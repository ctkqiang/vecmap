package app

import (
	_ "embed"
)

// manPage 内嵌 roff 格式的手册页。
//
// 内容与 docs/vecmap.1 保持同步（make manpage 生成该文件）。
//
//go:embed data/vecmap.1
var manPage string

// Man 返回 roff 格式的手册页文本。
//
// 返回内嵌手册页全文；可管道到 `man -l -` 或写入文件安装。
func (a *App) Man() string {
	return manPage
}
