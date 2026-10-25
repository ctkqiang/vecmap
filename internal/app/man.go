package app

import (
	_ "embed"
)

// manPage 内嵌英文 roff 手册页。
//
// 内容与 docs/vecmap.1 保持同步（make manpage 生成该文件）。
//
//go:embed data/vecmap.1
var manPage string

// manPageZH 内嵌中文 roff 手册页。
//
// 内容与 docs/vecmap.zh.1 保持同步（make manpage 生成该文件）。
//
//go:embed data/vecmap.zh.1
var manPageZH string

// Man 返回 roff 格式的手册页文本。
//
// 按当前界面语言返回英文或中文手册页；
// 可管道到 `man -l -` 或写入文件安装。
func (a *App) Man() string {
	if a != nil && a.language == "zh" {
		return manPageZH
	}
	return manPage
}
