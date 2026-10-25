package app

import "fmt"

const bashCompletion = `# bash completion for vecmap
_vecmap_complete() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local commands="scan discover dump sessions report advisories delete version help man completion"
    local common="--db --lang --verbose --help"
    local scan_flags="--authorize --name --mode --ports --timeout --concurrency --rate --insecure --fuzz --extract --collection --namespace --max-records --batch --vectors --user-agent --proxy --header --api-key --bearer --user --pass --database --dsn --scope-cidr --scope-domain --scope-port --exclude-cidr --exclude-domain --advisories --dry-run"
    case "$prev" in
        --mode) COMPREPLY=( $(compgen -W "standard deep" -- "$cur") ); return ;;
        --lang) COMPREPLY=( $(compgen -W "en zh" -- "$cur") ); return ;;
        --format) COMPREPLY=( $(compgen -W "markdown json html" -- "$cur") ); return ;;
        completion) COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") ); return ;;
    esac
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return
    fi
    case "${COMP_WORDS[1]}" in
        scan|dump) COMPREPLY=( $(compgen -W "$common $scan_flags" -- "$cur") ); return ;;
        discover) COMPREPLY=( $(compgen -W "$common --authorize --name --ports --timeout --concurrency --scope-cidr --scope-domain --exclude-cidr --exclude-domain --dry-run" -- "$cur") ); return ;;
        report) COMPREPLY=( $(compgen -W "$common --session --format --output" -- "$cur") ); return ;;
        *) COMPREPLY=( $(compgen -W "$common" -- "$cur") ); return ;;
    esac
}
complete -F _vecmap_complete vecmap
`

const zshCompletion = `#compdef vecmap
# zsh completion for vecmap
_arguments -C \
  '1:command:(scan discover dump sessions report advisories delete version help man completion)' \
  '*::arg:->args'
case $words[1] in
  scan|dump)
    _arguments \
      '--authorize[confirm written authorization]' \
      '--mode[scan mode]:mode:(standard deep)' \
      '--ports[ports]:ports:' \
      '--timeout[request timeout]:duration:' \
      '--extract[extract records]' \
      '--vectors[include vector samples]' \
      '--collection[collection filter]:collection:' \
      '--namespace[namespace filter]:namespace:' \
      '--max-records[record limit]:records:' \
      '--api-key[API key]:key:' \
      '--bearer[bearer token]:token:' \
      '--user[basic auth username]:user:' \
      '--pass[basic auth password]:pass:' \
      '--dsn[postgres DSN]:dsn:' \
      '--scope-cidr[authorized CIDR]:cidr:' \
      '--scope-domain[authorized domain]:domain:' \
      '--exclude-cidr[excluded CIDR]:cidr:' \
      '--exclude-domain[excluded domain]:domain:' \
      '--lang[UI language]:lang:(en zh)' \
      '--db[database path]:path:_files' \
      '--verbose[verbose logging]' \
      '--help[show help]' \
      '*:target:_files'
    ;;
  discover)
    _arguments \
      '--authorize[confirm written authorization]' \
      '--ports[ports]:ports:' \
      '--timeout[probe timeout]:duration:' \
      '--scope-cidr[authorized CIDR]:cidr:' \
      '--exclude-domain[excluded domain]:domain:' \
      '--lang[UI language]:lang:(en zh)' \
      '--verbose[verbose logging]' \
      '*:host:_files'
    ;;
  report)
    _arguments \
      '--session[session ID]:session:' \
      '--format[report format]:format:(markdown json html)' \
      '--output[output file]:path:_files' \
      '--lang[UI language]:lang:(en zh)' \
      '--verbose[verbose logging]'
    ;;
  delete)
    _arguments \
      '--session[session ID]:session:' \
      '--lang[UI language]:lang:(en zh)'
    ;;
esac
`

// Completion 返回 bash 或 zsh 的静态补全脚本。
//
// 参数 shell 为 bash 或 zsh；其他值返回错误。
// 返回脚本文本；将输出 source 进当前 shell 即可生效。
func (a *App) Completion(shell string) (string, error) {
	switch shell {
	case "bash":
		return bashCompletion, nil
	case "zsh":
		return zshCompletion, nil
	default:
		return "", fmt.Errorf("unsupported shell %q (use bash or zsh)", shell)
	}
}
