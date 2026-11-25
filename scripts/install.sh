#!/usr/bin/env bash
# Link Observatory managed node installer.
# Link Observatory managed updates v1.
set +x +v
set -euo pipefail
umask 077

# The release workflow stamps the artifact digests before hashing this installer.
installer_release_tag=
installer_sha_amd64=
installer_sha_arm64=

fail() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

usage() {
    printf '%s\n' '首次安装：bash install.sh --manager HTTPS_URL --node NODE_ID [--token TOKEN] [--release-url GITHUB_RELEASE_URL]' \
        '省略 --token 时从终端或标准输入读取注册码。' \
        '管理节点：bash /path/to/node/install.sh' \
        '直接更新：/path/to/node/install.sh --update [--gh-proxy HTTPS_URL]' \
        '查看状态：/path/to/node/install.sh --status' \
        '下载方式：--gh-proxy HTTPS_URL 通过自定义代理下载，--gh-proxy "" 改为直连。' \
        '直接卸载：/path/to/node/install.sh uninstall' \
        'root 节点：/opt/link-observatory/install.sh（多节点时添加 --node NODE_ID）'
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "缺少所需命令 $1"
}

validate_node() {
    [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || fail '节点标识须由字母、数字、下划线、点或连字符组成'
}

validate_release() {
    [[ $1 =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/releases/download/[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] ||
        fail '发布地址须指向固定 GitHub Release 的下载路径'
}

normalize_gh_proxy() {
    local value=$1 port
    local format='^https://([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\])(:([0-9]{1,5}))?(/[A-Za-z0-9._~-]+)*$'
    if [[ -n $value ]]; then
        while [[ $value == */ ]]; do value=${value%/}; done
        [[ ${#value} -le 512 && $value =~ $format ]] || fail 'gh-proxy 须为 HTTPS 地址，可包含端口或路径前缀'
        port=${BASH_REMATCH[3]}
        [[ -z $port ]] || (( 10#$port >= 1 && 10#$port <= 65535 )) || fail 'gh-proxy 端口无效'
        [[ "$value/" != */./* && "$value/" != */../* ]] || fail 'gh-proxy 路径不可包含 . 或 ..'
    fi
    gh_proxy=$value
}

release_asset() {
    printf '%s%s/%s' "${gh_proxy:+$gh_proxy/}" "$1" "$2"
}

download_mode() {
    if [[ -n $gh_proxy ]]; then
        printf 'gh-proxy（%s）' "$gh_proxy"
    else
        printf '直连 GitHub'
    fi
}

check_root_owned() {
    local path=$1 mode
    [[ -O $path ]] || fail "路径不属于当前账号：$path"
    mode=$(stat -c %a -- "$path") || fail "无法检查路径权限：$path"
    (( (8#$mode & 022) == 0 )) || fail "路径允许其他账号写入：$path"
}

check_directories() {
    local path
    for path in "$@"; do
        [[ ! -L $path ]] || fail "节点路径不能是符号链接：$path"
        if [[ $system_install == true && -e $path ]]; then
            [[ -d $path ]] || fail "节点路径不是目录：$path"
            check_root_owned "$path"
        fi
    done
}

check_root_files() {
    local path
    for path in "$@"; do
        [[ ! -L $path ]] || fail "节点文件不能是符号链接：$path"
        if [[ -e $path ]]; then
            [[ -f $path ]] || fail "节点文件不是普通文件：$path"
            check_root_owned "$path"
        fi
    done
}

check_node() {
    local dir=$1
    check_directories "$dir"
    if [[ $system_install == true ]]; then
        check_root_files "$dir/link-probe" "$dir/settings" "$dir/install.sh" "$dir/agent.log" \
            "$dir/credentials.json" "$dir/reports.json" "$dir/run.lock" "$dir/nexttrace" "$dir/route-program"
    fi
}

read_settings() {
    {
        IFS= read -r saved_manager && IFS= read -r saved_release || fail '节点配置不完整'
        IFS= read -r saved_proxy || saved_proxy=
    } < "$1/settings"
    validate_release "$saved_release"
    if [[ $proxy_supplied == false ]]; then
        normalize_gh_proxy "$saved_proxy"
    fi
}

download() {
    local url=$1 output=$2 redirects=${3:-20}
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
            --connect-timeout 10 --max-time 180 --retry 2 --max-redirs "$redirects" \
            -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --timeout=30 --tries=3 --max-redirect="$redirects" -q -O "$output" "$url"
    else
        fail '缺少下载命令 curl 或 wget'
    fi
}

verify() {
    (
        cd "$stage_dir"
        printf '%s  %s\n' "$2" "$1" | sha256sum -c -
    ) || fail "下载文件校验失败：$1"
}

clean_stage() {
    if [[ -n $launcher_temp ]]; then
        rm -f -- "$launcher_temp"
    fi
    if [[ -n $stage_dir ]]; then
        rm -rf -- "$stage_dir"
    fi
    if [[ -n $migration_stage ]]; then
        rm -rf -- "$migration_stage"
    fi
    if [[ -n $migration_archive ]]; then
        if [[ -d $migration_archive/original && ! -d $node_dir ]] &&
            ! mv -T -- "$migration_archive/original" "$legacy_node_dir"; then
            printf '旧节点文件保存在 %s/original，请从该目录恢复。\n' "$migration_archive" >&2
            return
        fi
        rm -rf -- "$migration_archive"
    fi
    if [[ $migration_was_running == true && ! -d $node_dir && -d $legacy_node_dir ]]; then
        node_dir=$legacy_node_dir
        agent="$node_dir/link-probe"
    fi
    if [[ $migration_was_running == true ]]; then
        start_node || printf '节点保存在 %s，可运行该目录中的 install.sh 恢复。\n' "$node_dir" >&2
    fi
}

start_node() {
    local started_pid attempt
    [[ -x $agent && -f $node_dir/credentials.json ]] || {
        printf '%s\n' '节点尚未完成安装或注册，请重新安装。' >&2
        return 1
    }
    if "$agent" status --dir "$node_dir" >/dev/null 2>&1; then
        return 0
    fi

    : > "$node_dir/agent.log"
    nohup "$agent" run --dir "$node_dir" </dev/null >>"$node_dir/agent.log" 2>&1 8>&- 9>&- &
    started_pid=$!
    for ((attempt = 0; attempt < 50; attempt++)); do
        if "$agent" status --dir "$node_dir" >/dev/null 2>&1; then
            printf '节点已启动：%s\n' "$node"
            return 0
        fi
        kill -0 "$started_pid" 2>/dev/null || break
        sleep 0.1
    done
    printf '节点未确认启动，查看日志：%s\n' "$node_dir/agent.log" >&2
    return 1
}

stop_node() {
    local dir=${1:-$node_dir}
    if [[ -x $dir/link-probe ]]; then
        "$dir/link-probe" stop --dir "$dir"
    elif [[ -e $dir/run.lock ]]; then
        printf '%s\n' '运行文件缺失，无法确认进程已停止。请恢复节点二进制后重试。' >&2
        return 1
    fi
}

find_installed_node() {
    local dir candidate=
    for dir in "$nodes_dir"/*; do
        [[ -d $dir && ! -L $dir && -f $dir/settings ]] || continue
        [[ -z $candidate ]] || fail '已安装多个节点，请添加 --node NODE_ID'
        candidate=${dir##*/}
    done
    [[ -n $candidate ]] || fail '当前账号下没有已安装的节点'
    node=$candidate
}

migrate_legacy_node() {
    local old_agent="$legacy_node_dir/link-probe"
    check_node "$legacy_node_dir"
    [[ -f $legacy_node_dir/settings && -f $legacy_node_dir/credentials.json ]] ||
        fail '旧节点尚未完成安装或注册，请先用旧目录中的管理脚本检查'
    read_settings "$legacy_node_dir"
    [[ -z $manager || $manager == "$saved_manager" ]] || fail '旧节点已配置其他管理端'
    if [[ -x $old_agent ]] && "$old_agent" status --dir "$legacy_node_dir" >/dev/null 2>&1; then
        migration_was_running=true
    fi
    stop_node "$legacy_node_dir" || fail '无法停止旧节点，已保留原安装'

    # Stage on the destination filesystem, then retire the old path with a local rename.
    migration_stage=$(mktemp -d "$nodes_dir/.migrate-$node.XXXXXXXX")
    cp -a -- "$legacy_node_dir/." "$migration_stage/" || fail '复制旧节点失败，已保留原安装'
    rm -f -- "$migration_stage/run.sock"
    cp -- "$script_path" "$migration_stage/install.sh"
    chmod 700 "$migration_stage/install.sh"
    migration_archive=$(mktemp -d "$legacy_nodes_dir/.migrate-$node.XXXXXXXX")
    mv -T -- "$legacy_node_dir" "$migration_archive/original" || fail '无法移动旧节点，已保留原安装'
    mv -T -- "$migration_stage" "$node_dir" || fail '无法启用新节点目录，正在恢复原安装'
    migration_stage=
    install_launcher
    printf '已将节点迁移到 %s\n' "$node_dir"
}

install_launcher() {
    [[ $system_install == true ]] || return 0
    launcher_temp=$(mktemp "$app_dir/.install.sh.XXXXXXXX")
    cp -- "$script_path" "$launcher_temp"
    chmod 700 "$launcher_temp"
    mv -fT -- "$launcher_temp" "$app_dir/install.sh"
    launcher_temp=
}

register_node() {
    local enroll_token=
    if [[ $token_supplied == true ]]; then
        enroll_token=$inline_token
        unset inline_token
    elif [[ -t 0 ]]; then
        IFS= read -r -s -p '请输入管理端的一次性注册码：' enroll_token || return 1
        printf '\n' >&2
    else
        IFS= read -r enroll_token || return 1
    fi
    [[ -n $enroll_token ]] || fail '注册码不能为空'
    printf '%s\n' "$enroll_token" |
        "$agent" register --manager "$manager" --node "$node" --dir "$node_dir"
}

registered() {
    local binary=${1:-$agent}
    # The agent checks its persisted enrollment before reading the token.
    [[ -x $binary && -f $node_dir/credentials.json ]] &&
        "$binary" register --manager "$manager" --node "$node" --dir "$node_dir" </dev/null >/dev/null 2>&1
}

print_node_commands() {
    printf '使用安装本节点的同一账号执行以下命令。\n'
    if [[ $system_install == true ]]; then
        printf '节点管理：%q --node %q\n' "$app_dir/install.sh" "$node"
        printf '一键卸载：%q --node %q uninstall\n' "$app_dir/install.sh" "$node"
    else
        printf '节点管理：bash %q\n' "$node_dir/install.sh"
        printf '一键卸载：%q uninstall\n' "$node_dir/install.sh"
    fi
}

usable_nexttrace() {
    local candidate=$1 permissions directory help
    [[ $candidate == /* && -f $candidate && -x $candidate ]] || return 1
    if [[ $system_install == true ]]; then
        directory=$candidate
        while [[ $directory != / ]]; do
            [[ -O $directory ]] || return 1
            permissions=$(stat -c %a -- "$directory") || return 1
            (( (8#$permissions & 022) == 0 )) || return 1
            directory=$(dirname -- "$directory")
        done
    fi
    help=$(timeout 5s "$candidate" --help 2>&1) || true
    [[ $help == *--json* ]]
}

prepare_nexttrace() {
    local candidate asset expected base
    if candidate=$(command -v nexttrace) &&
        candidate=$(realpath "$candidate") &&
        usable_nexttrace "$candidate"; then
        printf '%s\n' "$candidate" > "$stage_dir/route-program"
        printf '复用本机 NextTrace：%s\n' "$candidate"
        return
    fi

    base=https://github.com/nxtrace/NTrace-core/releases/download/v1.7.6
    case "$1" in
        link-probe-linux-amd64)
            asset=nexttrace_linux_amd64
            expected=3868c8190c961b534b8f2d0ed528796fc48d46a818ee5268fe2dfc6aa44b3a5e ;;
        link-probe-linux-arm64)
            asset=nexttrace_linux_arm64
            expected=e4c4e818f6cebf8d8ee3df3976a304c8bac2bb3bea3160a23fd5bce18095c9e6 ;;
    esac
    if [[ -x $node_dir/nexttrace ]] &&
        printf '%s  %s\n' "$expected" "$node_dir/nexttrace" | sha256sum -c --status -; then
        printf '%s\n' "$node_dir/nexttrace" > "$stage_dir/route-program"
        return
    fi
    printf '正在下载完整版 NextTrace。\n'
    candidate="$stage_dir/nexttrace"
    if download "$(release_asset "$base" "$asset")" "$candidate" &&
        printf '%s  %s\n' "$expected" "$candidate" | sha256sum -c --status - &&
        chmod 700 "$candidate"; then
        printf '%s\n' "$node_dir/nexttrace" > "$stage_dir/route-program"
        return
    fi
    rm -f -- "$candidate"
    : > "$stage_dir/route-program"
    printf 'NextTrace 下载失败。路由追踪暂不可用，可重新运行本地 install.sh 更新。\n' >&2
}

install_node() {
    local artifact expected was_running=false
    if [[ $action == update && ! -f $node_dir/credentials.json ]]; then
        fail '节点尚未注册，请重新运行管理端的注册命令'
    fi
    need sha256sum
    need nohup
    case "$(uname -m)" in
        x86_64) artifact=link-probe-linux-amd64; expected=$installer_sha_amd64 ;;
        aarch64|arm64) artifact=link-probe-linux-arm64; expected=$installer_sha_arm64 ;;
        *) fail '当前系统架构不受支持' ;;
    esac
    validate_release "$release"
    [[ $expected =~ ^[a-f0-9]{64}$ ]] || fail '请使用管理端生成的命令下载并校验正式安装脚本'
    [[ ${release##*/} == "$installer_release_tag" ]] || fail '请使用管理端生成的新版安装命令更新节点'

    stage_dir=$(mktemp -d "$nodes_dir/.install-$node.XXXXXXXX")
    download "$(release_asset "$release" "$artifact")" "$stage_dir/$artifact" || fail "无法下载安装文件：$artifact"
    verify "$artifact" "$expected"
    cp -- "$script_path" "$stage_dir/install.sh"
    chmod 700 "$stage_dir/$artifact" "$stage_dir/install.sh"
    mv -- "$stage_dir/$artifact" "$stage_dir/link-probe"
    prepare_nexttrace "$artifact"
    printf '%s\n' "$manager" "$release" "$gh_proxy" > "$stage_dir/settings"

    if [[ ! -d $node_dir ]]; then
        mv -- "$stage_dir" "$node_dir"
        stage_dir=
        install_launcher
    else
        [[ -f $node_dir/settings ]] || fail "目录已存在且归属未确认：$node_dir"
        if [[ -x $agent ]]; then
            if "$agent" status --dir "$node_dir" >/dev/null 2>&1; then
                was_running=true
            fi
            cp -- "$agent" "$stage_dir/previous-probe"
        fi
        if [[ $action == update ]] && ! registered "$stage_dir/link-probe"; then
            fail '现有节点凭证不可用，已保留原安装。请检查节点注册状态。'
        fi
        stop_node || fail '无法停止当前实例，已保留当前安装'
        mv -- "$stage_dir/link-probe" "$agent"
    fi

    if [[ $action != update ]] && ! registered; then
        register_node || fail '注册未完成，重新运行本地 install.sh 可继续安装'
    fi
    if ! start_node; then
        if [[ -n $stage_dir && -f $stage_dir/previous-probe ]] && stop_node; then
            mv -- "$stage_dir/previous-probe" "$agent"
            if [[ $was_running == true ]]; then
                start_node || true
            fi
        fi
        fail '启动未完成'
    fi
    if [[ -n $stage_dir ]]; then
        mv -- "$stage_dir/install.sh" "$node_dir/install.sh"
        mv -- "$stage_dir/settings" "$node_dir/settings"
        if [[ -f $stage_dir/nexttrace ]]; then
            mv -f -- "$stage_dir/nexttrace" "$node_dir/nexttrace"
        fi
        if [[ -f $stage_dir/route-program ]]; then
            mv -f -- "$stage_dir/route-program" "$node_dir/route-program"
            if [[ -s $node_dir/route-program ]]; then
                rm -f -- "$node_dir/nexttrace-tiny"
            fi
        fi
        install_launcher
    fi
    print_node_commands
}

update_from_manager() {
    local origin=${saved_manager%/} metadata release_url expected proxy_supported filename
    local -a args
    [[ -f $node_dir/credentials.json ]] || fail '节点尚未注册，请重新运行管理端的注册命令'
    [[ $origin =~ ^https://[^/?#@[:space:]]+$ ]] || fail '本地更新需要节点已保存的管理端 HTTPS 地址'
    need sha256sum
    stage_dir=$(mktemp -d "$nodes_dir/.update-$node.XXXXXXXX")
    if [[ -n $managed_version ]]; then
        printf '管理端更新目标：%s\n' "$managed_version"
        release_url="https://github.com/ZikQ-Shmily/link-observatory/releases/download/$managed_version"
        expected=$managed_installer_sha
        proxy_supported=true
    else
        printf '正在获取发布信息，下载方式：%s\n' "$(download_mode)"
        metadata="$stage_dir/release"
        download "$origin/api/agent/installer-release" "$metadata" 0 ||
            fail '无法获取发布信息，请确认管理端已经升级'
        {
            IFS= read -r release_url && IFS= read -r expected && IFS= read -r proxy_supported
        } < "$metadata" || fail '管理端发布信息不完整'
    fi
    validate_release "$release_url"
    [[ $expected =~ ^[a-f0-9]{64}$ ]] || fail '管理端发布信息缺少有效的 SHA-256 校验值'
    args=(-e "$origin" --node "$node" --release-url "$release_url" --update)
    case "$proxy_supported" in
        true) args+=(--gh-proxy "$gh_proxy") ;;
        false)
            [[ -z $gh_proxy ]] || fail 'gh-proxy 需要 v0.1.10 或更新的探针发行版'
            case "${release_url##*/}" in
                v0.1.0|v0.1.1|v0.1.2|v0.1.3) fail '请从管理端生成固定旧版本的更新命令' ;;
            esac
            ;;
        *) fail '管理端发布信息无效' ;;
    esac
    filename="$stage_dir/install.sh"
    download "$(release_asset "$release_url" install.sh)" "$filename" || fail '下载 GitHub 安装脚本失败'
    verify install.sh "$expected"

    # The verified release installer acquires the directory lock itself.
    exec 8<&- 9<&-
    bash +x +v "$filename" "${args[@]}"
}

probe_state() {
    if [[ ! -x $agent ]]; then
        printf '主程序缺失'
    elif [[ ! -f $node_dir/credentials.json ]]; then
        printf '未完成注册'
    elif "$agent" status --dir "$node_dir" >/dev/null 2>&1; then
        printf '运行中'
    else
        printf '已停止'
    fi
}

show_status() {
    local version route_path
    version=$("$agent" version 2>/dev/null) || version='未知'
    printf '节点：%s\n运行状态：%s\n版本：%s\n管理端：%s\nGitHub 下载：%s\n安装目录：%s\n' \
        "$node" "$(probe_state)" "$version" "$saved_manager" "$(download_mode)" "$node_dir"
    if [[ -r $node_dir/route-program ]] && IFS= read -r route_path < "$node_dir/route-program" && [[ -x $route_path ]]; then
        printf 'NextTrace：%s\n' "$route_path"
    else
        printf 'NextTrace：不可用\n'
    fi
}

set_download_mode() {
    local value
    IFS= read -r -p '请输入 gh-proxy HTTPS 地址，留空改为直连：' value || fail '已取消设置'
    normalize_gh_proxy "$value"
    stage_dir=$(mktemp -d "$nodes_dir/.settings-$node.XXXXXXXX")
    printf '%s\n' "$saved_manager" "$saved_release" "$gh_proxy" > "$stage_dir/settings"
    mv -fT -- "$stage_dir/settings" "$node_dir/settings"
    printf 'GitHub 下载方式已保存：%s\n' "$(download_mode)"
}

uninstall_node() {
    if [[ ! -d $node_dir ]]; then
        printf '节点已卸载：%s\n' "$node"
        return
    fi
    [[ -f $node_dir/settings ]] || fail "目录归属未确认：$node_dir"
    stop_node || fail '无法确认节点进程已退出，已保留本机文件'
    rm -rf -- "$node_dir"
    printf '本机已卸载 %s。可在管理端吊销节点凭证。\n' "$node"
}

unset inline_token enroll_token
manager= node= release= action= inline_token= token_supplied=false
gh_proxy= proxy_supplied=false managed_version= managed_installer_sha=
while (( $# )); do
    case "$1" in
        -e|--manager|--node|--release-url|--gh-proxy|--managed-version|--installer-sha256)
            (( $# >= 2 )) || fail "$1 缺少参数"
            case "$1" in
                -e|--manager) manager=$2 ;;
                --node) node=$2 ;;
                --release-url) release=${2%/} ;;
                --managed-version) managed_version=$2 ;;
                --installer-sha256) managed_installer_sha=$2 ;;
                --gh-proxy) normalize_gh_proxy "$2"; proxy_supplied=true ;;
            esac
            shift 2 ;;
        -t|--token)
            (( $# >= 2 )) || fail '--token 缺少注册码'
            [[ -n $2 && $2 != *$'\n'* && $2 != *$'\r'* ]] || fail '注册码须为非空的单行内容'
            inline_token=$2; token_supplied=true; shift 2 ;;
        uninstall|--update|status|--status)
            [[ -z $action ]] || fail '一次只能执行一个节点操作'
            action=${1#--}; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "无法识别参数：$1" ;;
    esac
done
[[ $action != update || $token_supplied == false ]] || fail '更新节点无需提供注册码'

if [[ -n $managed_version || -n $managed_installer_sha ]]; then
    [[ $action == update && $proxy_supplied == false && -z $release && -z $manager &&
        $managed_version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ &&
        $managed_installer_sha =~ ^[a-f0-9]{64}$ ]] || fail '无效的管理端更新任务'
fi

[[ $(uname -s) == Linux ]] || fail '节点安装脚本仅支持 Linux'
system_install=false
user_home= app_dir= legacy_nodes_dir= legacy_node_dir=
stage_dir= launcher_temp= migration_stage= migration_archive= migration_was_running=false
if [[ ${HOME:-} == /* ]]; then
    user_home=$(cd -- "$HOME" 2>/dev/null && pwd -P) || user_home=
fi
if (( EUID == 0 )); then
    system_install=true
    app_dir=/opt/link-observatory
    nodes_dir="$app_dir/nodes"
    check_directories /opt "$app_dir" "$nodes_dir"
    check_root_files "$app_dir/install.sh"
    if [[ -f $app_dir/install.sh ]]; then
        grep -Fxq '# Link Observatory managed node installer.' "$app_dir/install.sh" ||
            fail '管理入口已存在且归属未确认，未覆盖该文件'
    fi
    if [[ -z $user_home || $user_home == / || ! -O $user_home ]]; then
        user_home=$(cd -- ~root 2>/dev/null && pwd -P) || user_home=
    fi
    if [[ -n $user_home && $user_home != / && -O $user_home ]]; then
        legacy_nodes_dir="$user_home/.local/share/link-monitor/nodes"
    fi
else
    [[ -n $user_home && $user_home != / && -O $user_home ]] || fail 'HOME 须是当前账号拥有的绝对路径'
    nodes_dir="$user_home/.local/share/link-monitor/nodes"
    check_directories "$user_home" "$user_home/.local" "$user_home/.local/share" "$user_home/.local/share/link-monitor" "$nodes_dir"
fi
script_path=${BASH_SOURCE[0]}
script_dir=$(cd -- "$(dirname -- "$script_path")" && pwd -P)
script_path="$script_dir/${script_path##*/}"
if [[ -z $node && ${script_dir%/*} == "$nodes_dir" ]]; then
    node=${script_dir##*/}
fi
if [[ -n $node || $system_install != true || $script_dir != "$app_dir" ]]; then
    validate_node "$node"
fi

if [[ -n $node && -n $legacy_nodes_dir ]]; then
    legacy_node_dir="$legacy_nodes_dir/$node"
fi
if [[ $action == status ]]; then
    if [[ -z $node ]]; then
        find_installed_node
        validate_node "$node"
    fi
    node_dir="$nodes_dir/$node"
    if [[ ! -d $node_dir && -d $legacy_node_dir ]]; then
        node_dir=$legacy_node_dir
    fi
    agent="$node_dir/link-probe"
    check_node "$node_dir"
    [[ -f $node_dir/settings ]] || fail '当前账号下找不到已安装的节点'
    read_settings "$node_dir"
    show_status
    exit 0
fi
if [[ ! -d $nodes_dir && ( $action == uninstall || $action == update ) && ! -d $legacy_node_dir ]]; then
    [[ $action != update ]] || fail '当前账号下找不到已安装的节点，无法更新'
    printf '节点已卸载：%s\n' "$node"
    exit 0
fi
if [[ $system_install == true && ! -d /opt ]]; then
    mkdir -m 755 -- /opt
fi
mkdir -p -- "$nodes_dir"
need flock
exec 9<"$nodes_dir"
flock -n 9 || fail '另一个节点管理操作正在运行，请稍后再试'
if [[ -z $node ]]; then
    find_installed_node
    validate_node "$node"
fi
node_dir="$nodes_dir/$node"
agent="$node_dir/link-probe"
check_node "$node_dir"
trap clean_stage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -n $legacy_node_dir && ( -e $legacy_node_dir || -L $legacy_node_dir ) ]]; then
    check_directories "$user_home" "$user_home/.local" "$user_home/.local/share" "$user_home/.local/share/link-monitor" "$legacy_nodes_dir"
    exec 8<"$legacy_nodes_dir"
    flock -n 8 || fail '旧目录正在执行节点管理操作，请稍后再试'
    if [[ -e $legacy_node_dir || -L $legacy_node_dir ]]; then
        [[ ! -e $node_dir ]] || fail '新旧目录均存在同名节点，请检查后再继续'
        [[ $action == update ]] || fail '发现旧版节点，请使用管理端生成的更新命令迁移'
        migrate_legacy_node
    fi
fi

if [[ $action == uninstall ]]; then
    uninstall_node
elif [[ -f $node_dir/settings ]]; then
    read_settings "$node_dir"
    [[ -z $manager || $manager == "$saved_manager" ]] || fail '此节点已配置其他管理端'
    manager=$saved_manager
    release=${release:-$saved_release}
    local_entry=false
    if [[ $script_dir == "$node_dir" || ( $system_install == true && $script_dir == "$app_dir" ) ]]; then
        local_entry=true
    fi
    if [[ $action == update ]]; then
        if [[ -n $managed_version && $local_entry != true ]]; then
            fail '管理端更新需使用节点本地安装脚本'
        fi
        if [[ $local_entry == true ]]; then
            update_from_manager
        else
            install_node
        fi
        exit 0
    fi
    if [[ $token_supplied == true ]]; then
        if [[ $release != "$saved_release" || $gh_proxy != "$saved_proxy" || ! -x $agent ]]; then
            install_node
        else
            if ! "$agent" status --dir "$node_dir" >/dev/null 2>&1; then
                registered || register_node || fail '注册未完成，请重新执行管理端部署命令'
                need nohup
                start_node || fail '启动未完成'
            fi
            print_node_commands
        fi
        exit 0
    fi
    [[ -t 0 ]] || fail '请使用交互式终端打开节点管理菜单'
    printf '节点 %s（%s）\n' "$node" "$(probe_state)"
    printf 'GitHub 下载：%s\n' "$(download_mode)"
    printf '%s\n' '1) 启动 / 重启' '2) 更新 / 重装' '3) 卸载' \
        '4) 当前运行状态' '5) 设置 GitHub 下载方式' '0) 退出'
    IFS= read -r -p '请选择：' choice
    case "$choice" in
        1) need nohup; stop_node && start_node ;;
        2)
            if [[ $local_entry == true ]]; then
                update_from_manager
            else
                install_node
            fi
            ;;
        3) uninstall_node ;;
        4) show_status ;;
        5) set_download_mode ;;
        0) exit 0 ;;
        *) fail '无效选项' ;;
    esac
else
    [[ $action != update ]] || fail '当前账号下找不到已安装的节点，无法更新'
    [[ $manager == https://* || $manager =~ ^http://(localhost|127(\.[0-9]{1,3}){3}|\[::1\])(:[0-9]{1,5})?/?$ ]] ||
        fail '首次安装需要管理端 HTTPS 地址'
    [[ ! -e $node_dir ]] || fail "目录已存在且归属未确认：$node_dir"
    install_node
fi
