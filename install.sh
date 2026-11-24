#!/usr/bin/env bash
{
    set +x +v
    set -euo pipefail
    umask 077

    fail() { printf '错误：%s\n' "$*" >&2; exit 1; }

    base=https://github.com/ZikQ-Shmily/link-observatory/releases
    proxy=
    args=()
    while (( $# )); do
        case "$1" in
            --gh-proxy)
                (( $# >= 2 )) || fail '缺少 gh-proxy 地址'
                proxy=$2
                while [[ $proxy == */ ]]; do proxy=${proxy%/}; done
                [[ -z $proxy || $proxy =~ ^https://[^/?#@[:space:]]+(/[A-Za-z0-9._~-]+)*$ ]] ||
                    fail 'gh-proxy 须为 HTTPS 地址'
                shift 2 ;;
            -t|--token)
                (( $# >= 2 )) || fail '缺少注册令牌'
                args+=(-t "$2")
                shift 2 ;;
            --manager|-e|--node)
                (( $# >= 2 )) || fail "$1 缺少参数"
                args+=("$1" "$2")
                shift 2 ;;
            --update)
                args+=("$1")
                shift ;;
            -h|--help)
                printf '%s\n' '安装：--manager HTTPS_URL --node NODE_ID --token TOKEN [--gh-proxy HTTPS_URL]' \
                    '更新：--manager HTTPS_URL --node NODE_ID --update [--gh-proxy HTTPS_URL]'
                exit 0 ;;
            *) fail "无法识别的参数：$1" ;;
        esac
    done

    (( ${#args[@]} )) || fail '请使用管理端生成的安装或更新命令'
    installer=$(mktemp)
    trap 'rm -f -- "$installer"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    curl -fsSL --proto '=https' --connect-timeout 10 --max-time 180 \
        -o "$installer" "${proxy:+$proxy/}$base/latest/download/install.sh" ||
        fail '下载最新 GitHub 安装脚本失败'

    # Match the version in the downloaded asset, so its binary stays on the
    # same release even if GitHub publishes another version during installation.
    tag=$(sed -n "s/^installer_release_tag='\(v[0-9][0-9.]*\)'$/\1/p" "$installer")
    [[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
        fail '最新发行版安装脚本缺少有效的版本号'
    bash "$installer" --release-url "$base/download/$tag" --gh-proxy "$proxy" "${args[@]}"
}
