#!/usr/bin/env bash
set +x +v
set -euo pipefail
umask 077

# MANAGER_BOOTSTRAP_CONFIG

installer_file=

fail() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n $installer_file ]]; then
        rm -f -- "$installer_file"
    fi
}

main() {
    local node token= manager_flag=-e menu_update=false remaining= actual_hash
    local -a args
    export -n token

    # When piped into bash -s, wait for EOF before performing installation actions.
    if [[ -z ${BASH_SOURCE[0]-} ]]; then
        if IFS= read -r remaining || [[ -n $remaining ]]; then
            fail '安装入口内容不完整或格式不正确，请重新复制管理端命令'
        fi
    fi

    if (( $# == 1 )) && [[ $1 == -h || $1 == --help ]]; then
        printf '%s\n' '注册：-t 节点ID:一次性注册码' '更新：--node 节点ID（使用安装节点的同一账号）'
        return
    fi
    (( $# == 2 )) || fail '请提供 -t 节点ID:一次性注册码，或 --node 节点ID'
    case "$1" in
        -t)
            [[ $2 == *:* ]] || fail '注册码格式须为 节点ID:一次性注册码'
            node=${2%%:*}
            token=${2#*:}
            [[ -n $token && $token != *$'\n'* && $token != *$'\r'* ]] || fail '注册码须为非空的单行内容'
            ;;
        --node)
            node=$2
            ;;
        *) fail '请使用 -t 或 --node' ;;
    esac
    [[ $node =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || fail '节点标识无效'
    [[ -n ${manager:-} && -n ${release:-} && ${installer_hash:-} =~ ^[a-f0-9]{64}$ ]] ||
        fail '管理端尚未配置发行版安装器'
    case "${release##*/}" in
        v0.1.0|v0.1.1|v0.1.2) manager_flag=--manager; menu_update=true ;;
        v0.1.3) menu_update=true ;;
    esac
    if [[ -z $token && $menu_update == true ]] && ! { exec 3</dev/tty; } 2>/dev/null; then
        fail '此版本需要交互式终端更新，请使用安装节点的同一账号直接运行命令'
    fi
    command -v sha256sum >/dev/null 2>&1 || fail '缺少所需命令 sha256sum'

    installer_file=$(mktemp) || fail '无法创建临时安装文件'
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if command -v wget >/dev/null 2>&1; then
        wget -qO "$installer_file" "$release/install.sh" || fail '下载发行版安装器失败'
    elif command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
            -o "$installer_file" "$release/install.sh" || fail '下载发行版安装器失败'
    else
        fail '缺少下载命令 wget 或 curl'
    fi
    actual_hash=$(sha256sum < "$installer_file") || fail '无法计算发行版安装器 SHA-256'
    [[ ${actual_hash%% *} == "$installer_hash" ]] || fail '发行版安装器 SHA-256 校验失败'

    args=("$manager_flag" "$manager" --node "$node" --release-url "$release")
    if [[ -z $token && $menu_update == true ]]; then
        bash +x +v "$installer_file" "${args[@]}" <&3 3<&-
    elif [[ -z $token ]]; then
        bash +x +v "$installer_file" "${args[@]}" --update </dev/null
    elif [[ $manager_flag == --manager ]]; then
        printf '%s\n' "$token" | bash +x +v "$installer_file" "${args[@]}"
    else
        bash +x +v "$installer_file" "${args[@]}" -t "$token" </dev/null
    fi
}

main "$@"
