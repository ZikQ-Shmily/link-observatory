#!/usr/bin/env bash
{
    set +x +v
    set -euo pipefail
    umask 077

    fail() { printf '错误：%s\n' "$*" >&2; exit 1; }

    proxy=
    node=
    args=("$@")
    while (( $# )); do
        case "$1" in
            --gh-proxy)
                (( $# >= 2 )) || fail '缺少 gh-proxy 地址'
                proxy=$2
                while [[ $proxy == */ ]]; do proxy=${proxy%/}; done
                [[ -z $proxy || $proxy =~ ^https://[^/?#@[:space:]]+(/[A-Za-z0-9._~-]+)*$ ]] ||
                    fail 'gh-proxy 须为 HTTPS 地址'
                shift 2 ;;
            --node)
                (( $# >= 2 )) || fail '缺少回程端标识'
                node=$2
                shift 2 ;;
            --manager|-e|--token|-t)
                (( $# >= 2 )) || fail "$1 缺少参数"
                shift 2 ;;
            --update) shift ;;
            -h|--help)
                printf '%s\n' '在监测目标主机运行管理端生成的回程部署命令。'
                exit 0 ;;
            *) fail "无法识别的参数：$1" ;;
        esac
    done
    [[ $node =~ ^return-[a-f0-9]{16}$ ]] || fail '请使用管理端生成的回程部署命令'

    installer=$(mktemp)
    trap 'rm -f -- "$installer"' EXIT
    url=https://raw.githubusercontent.com/ZikQ-Shmily/link-observatory/main/install.sh
    curl -fsSL --proto '=https' --connect-timeout 10 --max-time 180 \
        -o "$installer" "${proxy:+$proxy/}$url" || fail '下载 GitHub 安装入口失败'
    bash "$installer" "${args[@]}"
}
