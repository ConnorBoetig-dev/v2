#!/bin/bash
#
# NetworkMapper v2 - Automated Local Setup Script
#
# A visually-enhanced, user-friendly setup experience.
#

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
PYTHON_VERSION_MAJOR=3
PYTHON_VERSION_MINOR=8
VENV_DIR="venv"

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
    echo -e "${BLUE}"
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

# --- Helper Functions ---
command_exists() { command -v "$1" >/dev/null 2>&1; }

spinner() {
    local pid=$1
    local message=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    tput civis
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % ${#spin} ))
        printf "\r${CYAN}${BOLD} %c ${NC} %s" "${spin:$i:1}" "$message"
        sleep 0.1
    done
    tput cnorm
    printf "\r%s\n" "$(tput el)"
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

install_system_deps() {
    log_step "📡 Checking system-wide scanning tools..."
    deps=("nmap" "masscan" "arp-scan")
    missing_deps=()

    for dep in "${deps[@]}"; do
        if command_exists "$dep"; then
            log_info "$dep is installed."
        else
            log_warn "$dep is NOT installed."
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_deps[*]}"
        echo ""
        read -p "Attempt to install them now? (Requires sudo) (y/N) " -n 1 -r; echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Aborting. Please install missing tools manually."
            exit 1
        fi

        log_step "Requesting administrator privileges for installation..."
        if ! sudo -v; then
            log_error "Sudo authentication failed. Cannot proceed with installation."
            exit 1
        fi
        log_info "Sudo access granted."

        if [[ "$OS_TYPE" == "linux" ]]; then
            log_step "Installing with apt..."
            (sudo apt-get update > /dev/null 2>&1) &
            spinner $! "Updating package lists..."
            log_info "Package lists updated successfully."
            (sudo apt-get install -y "${missing_deps[@]}" > /dev/null 2>&1) &
            spinner $! "Installing ${missing_deps[*]}..."
            log_info "Packages installed successfully."


        elif [[ "$OS_TYPE" == "darwin" ]]; then
            if ! command_exists brew; then log_error "Homebrew not found. Please install it: https://brew.sh/"; exit 1; fi
            log_step "Attempting to install with Homebrew..."; brew install "${missing_deps[@]}"
        fi

        for dep in "${missing_deps[@]}"; do
            if ! command_exists "$dep"; then
                log_error "Failed to install $dep. Please install it manually and re-run setup."
                exit 1
            fi
        done
        log_info "All system dependencies are now installed!"
    else
        log_info "All system dependencies are present."
    fi
}

setup_venv() {
    log_step "📦 Creating Python virtual environment..."
    if [ -d "$VENV_DIR" ]; then log_info "Virtual environment already exists."; else
        python3 -m venv "$VENV_DIR"; log_info "Virtual environment created in ./${VENV_DIR}/"; fi
}

install_python_deps() {
    log_step "🧩 Installing Python packages..."
    source "${VENV_DIR}/bin/activate"
    (pip install --upgrade pip > /dev/null 2>&1) &
    spinner $! "Upgrading pip..."
    log_info "Pip upgraded successfully."
    (pip install -r requirements.txt > /dev/null 2>&1) &
    spinner $! "Installing dependencies from requirements.txt... (this may take a moment)"
    log_info "Dependencies installed successfully."
    deactivate
    log_info "All Python packages installed successfully."
}

create_directories() {
    log_step "🗂️  Creating output directories..."
    mkdir -p output/{scans,reports,exports,logs,cache,config,changes,annotations}
    log_info "Output directory structure is ready."
}

print_final_message() {
    ART_COLOR_1='\033[0;36m'
    ART_COLOR_2='\033[0;35m'
    ART_COLOR_3='\033[0;34m'

    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${ART_COLOR_1}"
    cat << "EOF"
               ,::%%n
            ,-::%%%%%%=.
           /:::%%%(:  "-:.
         ,:::%:%%%f:     :
         f:::%:%%%%,   ."`.
        i::::%%:%%%%, .',-t
       j::::::%:%%%%i 'i  `i
       :::::::%:%%%%%  :_-=".
EOF
    echo -e "${ART_COLOR_2}"
    cat << "EOF"
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
    echo -e "${ART_COLOR_3}"
    cat << "EOF"
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
    echo ""
    echo -e "Your local environment is now prepared."
    echo -e "The final step is to create the system-wide command."
    echo ""
    echo -e "  - ${BOLD}To complete the installation, run:${NC}"
    echo -e "    ${CYAN}make mapper${NC}"
    echo ""
    echo -e "This will create the '${BOLD}mapper${NC}' command, allowing you to run the tool from anywhere."
    echo ""
}


main() {
    print_banner
    echo ""
    echo "Initiating setup sequence..."

    check_os
    check_python
    install_system_deps
    setup_venv
    install_python_deps
    create_directories

    print_final_message
}

main
