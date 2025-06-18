#!/bin/bash
#
# NetworkMapper v2 - Automated Local Setup Script
# A visually-enhanced, user-friendly setup experience.
#

# Exit immediately if a command exits with a non-zero status.
set -e

# --- THIS IS THE CRUCIAL FIX FOR THE SCRIPT'S LOCATION ---
# Get the absolute path of the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
# Set the project root as the parent directory of the script's directory
PROJECT_ROOT="$SCRIPT_DIR/.."
# --- END OF FIX ---

# --- Configuration ---
PYTHON_VERSION_MAJOR=3
PYTHON_VERSION_MINOR=8
# All paths should now be relative to the PROJECT_ROOT
VENV_DIR="$PROJECT_ROOT/venv"

# --- Colors for ANSI escape codes ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}${BOLD}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}${BOLD}[!]${NC} $1"; }
log_error() { echo -e "${RED}${BOLD}[✗]${NC} $1"; }
log_step() { echo -e "\n${CYAN}${BOLD}==>${NC} ${BOLD}$1${NC}"; }
print_banner() { 
    clear
    echo -e "${CYAN}"
    cat << "EOF"
                                              _..
                                          .qd$$$$bp.
                                        .q$$$$$$$$$$m.
                                       .$$$$$$$$$$$$$$
                                     .q$$$$$$$$$$$$$$$$
                                    .$$$$$$$$$$$$P\$$$$;
                                  .q$$$$$$$$$P^"_.`;$$$$
                                 q$$$$$$$P;\   ,  /$$$$P
                               .$$$P^::Y$/`  _  .:.$$$/
                              .P.:..    \ `._.-:.. \$P
                              $':.  __.. :   :..    :'
                             /:_..::.   `. .:.    .'|
                           _::..          T:..   /  :
                        .::..             J:..  :  :
                     .::..          7:..   F:.. :  ;
                 _.::..             |:..   J:.. `./
            _..:::..               /J:..    F:.  :
          .::::..                .T  \:..   J:.  /
         /:::...               .' `.  \:..   F_o'
        .:::...              .'     \  \:..  J ;
        ::::...           .-'`.    _.`._\:..  \'
        ':::...         .'  `._7.-'_.-  `\:.   \
         \:::...   _..-'__.._/_.--' ,:.   b:.   \._
          `::::..-"_.'-"_..--"      :..   /):.   `.\
            `-:/"-7.--""            _::.-'P::..    \}
 _....------""""""            _..--".-'   \::..     `.
(::..              _...----"""  _..'       `---:..    `-.
 \::..      _.-""""   `""""---""                `::...___)
  `\:._.-"""                             fsc
EOF
    echo -e "${MAGENTA}${BOLD}                          Automated Setup v2.0${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "      Welcome! Preparing your system for Network Discovery."
    echo -e "${CYAN}======================================================================${NC}"
}
command_exists() { command -v "$1" >/dev/null 2>&1; }
spinner() {
    local pid=$1; local message=$2; local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; local i=0
    tput civis; while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % ${#spin} )); printf "\r${CYAN}${BOLD} %c ${NC} %s" "${spin:$i:1}" "$message"; sleep 0.1
    done; tput cnorm; printf "\r%s\n" "$(tput el)";
}
check_os() { 
    log_step "🛰️  Detecting Operating System..."
    OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
    if [[ "$OS_TYPE" == "linux" ]]; then log_info "Linux system detected.";
    elif [[ "$OS_TYPE" == "darwin" ]]; then log_info "macOS system detected.";
    else log_error "Unsupported OS: $OS_TYPE. Please use Linux, macOS, or WSL."; exit 1; fi
}
check_python() { 
    log_step "🐍 Checking Python version..."
    if ! command_exists python3; then
        log_error "python3 is not installed. Please install Python ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} or higher."
        exit 1
    fi
    PY_VERSION_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
    PY_VERSION_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
    if (( PY_VERSION_MAJOR < PYTHON_VERSION_MAJOR || (PY_VERSION_MAJOR == PYTHON_VERSION_MAJOR && PY_VERSION_MINOR < PYTHON_VERSION_MINOR) )); then
        log_error "Python ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}+ is required. You have ${PY_VERSION_MAJOR}.${PY_VERSION_MINOR}."
        exit 1
    fi
    log_info "Python ${PY_VERSION_MAJOR}.${PY_VERSION_MINOR} is ready."
}
check_command_in_path() { 
    local cmd_path; cmd_path=$(command -v "$1" 2>/dev/null)
    if [ -z "$cmd_path" ]; then return 1; fi
    case "$cmd_path" in
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/local/bin/*|/usr/local/sbin/*) return 0;;
        *) return 2;;
    esac
}

install_system_deps() { 
    log_step "📡 Verifying system-wide scanning tools..."
    deps=("nmap" "masscan" "arp-scan")
    missing_deps=()
    path_issue_deps=()
    path_issue_locations=()
    for dep in "${deps[@]}"; do
        check_command_in_path "$dep"
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then log_info "$dep is installed and in PATH.";
        elif [ $exit_code -eq 1 ]; then log_warn "$dep is NOT installed."; missing_deps+=("$dep");
        elif [ $exit_code -eq 2 ]; then
            local cmd_path=$(command -v "$dep");
            log_warn "Tool '$dep' is at '$cmd_path' but not in a standard system PATH."
            path_issue_deps+=("$dep"); path_issue_locations+=("$cmd_path"); fi
    done
    if [ ${#path_issue_deps[@]} -ne 0 ]; then
        log_error "Path Issue Detected for: ${path_issue_deps[*]}";
        echo -e "This tool can be fixed by creating a symbolic link in ${BOLD}/usr/local/bin/${NC}."
        read -p "Attempt to fix this automatically? (Requires sudo) (y/N) " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_step "Requesting privileges to fix paths..."; if ! sudo -v; then log_error "Sudo auth failed."; exit 1; fi
            for i in "${!path_issue_deps[@]}"; do
                sudo ln -sf "${path_issue_locations[i]}" "/usr/local/bin/${path_issue_deps[i]}";
            done; log_info "Paths fixed. Re-running verification..."; install_system_deps; return
        else log_error "Aborting. Please fix the PATH issue manually."; exit 1; fi
    fi
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_deps[*]}";
        read -p "Attempt to install them now? (Requires sudo) (y/N) " -n 1 -r; echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then log_error "Aborting. Please install missing tools manually."; exit 1; fi
        if ! sudo -v; then log_error "Sudo auth failed."; exit 1; fi; log_info "Sudo access granted."
        if [[ "$OS_TYPE" == "linux" ]]; then
            log_step "Installing with apt..."; (sudo apt-get update >/dev/null 2>&1) & spinner $! "Updating package lists..."; (sudo apt-get install -y "${missing_deps[@]}" >/dev/null 2>&1) & spinner $! "Installing ${missing_deps[*]}..."
        elif [[ "$OS_TYPE" == "darwin" ]]; then
            if ! command_exists brew; then log_error "Homebrew not found. Install it: https://brew.sh/"; exit 1; fi
            log_step "Installing with Homebrew..."; brew install "${missing_deps[@]}"
        fi
        log_step "Final verification..."; for dep in "${missing_deps[@]}"; do
            if ! command_exists "$dep"; then log_error "Failed to install '$dep'. Please install manually."; exit 1; fi
            log_info "$dep is now installed."
        done
        log_info "All system dependencies are now correctly installed!"
    elif [ ${#path_issue_deps[@]} -eq 0 ]; then
        log_info "All system dependencies are present and correctly configured."
    fi
}


setup_venv() {
    log_step "🐍 Creating Python virtual environment..."
    if [ -d "$VENV_DIR" ]; then log_info "Virtual environment already exists."; else
        python3 -m venv "$VENV_DIR"; log_info "Virtual environment created at '$VENV_DIR'"; fi
}

install_python_deps() {
    log_step "🐍 Installing Python packages..."
    source "${VENV_DIR}/bin/activate"

    local req_file="$PROJECT_ROOT/ops/requirements.txt"
    if [ ! -f "$req_file" ]; then
        log_error "Could not find requirements file at '$req_file'!"
        exit 1
    fi
    
    (
        pip install --upgrade pip > /dev/null 2>&1
        pip install -r "$req_file" > /dev/null 2>&1
    ) &
    spinner $! "Installing Python dependencies... (this may take a moment)"

    deactivate
    log_info "All Python packages installed successfully."
}

create_directories() {
    log_step "🗂️  Creating output directories..."
    mkdir -p "$PROJECT_ROOT"/output/{scans,reports,exports,logs,cache,config,changes,annotations}
    log_info "Output directory structure is ready."
}

print_final_message() { 
    ART_COLOR_1='\033[0;36m'; ART_COLOR_2='\033[0;35m'; ART_COLOR_3='\033[0;34m'
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${ART_COLOR_1}"; cat << "EOF"
               ,::%%n
            ,-::%%%%%%=.
           /:::%%%(:  "-:.
         ,:::%:%%%f:     :
         f:::%:%%%%,   ."`.
        i::::%%:%%%%, .',-t
       j::::::%:%%%%i 'i  `i
       :::::::%:%%%%%  :_-=".
EOF
    echo -e "${ART_COLOR_2}"; cat << "EOF"
      /:::::::%%%%%%%i      t
     ,:::::::::%%%%%%; .    ]
     f:::::::::%%%%%;  ,.-= j,-""-.
    /::::::::::l%%%%f <--"/,'      `.
   /::::::::::l%%%%;:: "`","         \
  /:::::::::::l%%%;:-:__.,"           \
 ;:::::::::::l%%%;::::: /              :
j::::::::::::l%%; ' '        .      __,|
:::::::;:-''"                `.  ,%8888&n
j::::::'  _.                  :`.n88%888&i
|:::::+,-"     ,-  _.n%%%n.. :::<&88%888&b
|::;+%%%n. ..:/  .n%%%%%%%%%. :::&888%888&
|:/%%%%%%%8+:i  +%%%%%*%%%o%%.::::&888%888&
`j%%*%%%%*88%|.%%%*%%%%%%%%%%|::::&88%88&i
`%%%%%%%%888888%%%%%%%*%%%%8::::::&88%88&H
 `%o%%%*%8o88888%%%%%%%%%888i::::/|&88%88&i
EOF
    echo -e "${ART_COLOR_3}"; cat << "EOF"
  `%%%%%%88888%%%88888888888;:::/ `888%888&
    `%%%8%%%%%%8888886888*88j::/   H888%88&h
      i%%*%%%%o%%88888888888i:/    `888%888&
      `%%%%%%%%%%%8888888888%Y      H888%88&i
       \%%%%%o%*%%%8888888%%/       `888%888&.
        `%%*%%%%%%%8888888%j         H8888%88&i
         \%%%%%%%%%%888888%f         i8888%8&t
EOF
    echo -e "${GREEN}${BOLD}      👻  Environment Setup Complete!  👻${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo ""; echo -e "  - ${BOLD}To Run Network Mapper :${NC}"; echo -e "    ${CYAN}make mapper${NC}";
}

main() {
    cd "$PROJECT_ROOT"
    
    print_banner
    echo ""
    echo "Initiating setup sequence from project root: $(pwd)"

    check_os
    check_python
    install_system_deps
    setup_venv
    install_python_deps
    create_directories

    print_final_message
}

main
