# Docker Socket Container Escape - Direct API PoC (Improved)

## ⚠️ WARNING: EDUCATIONAL PURPOSE ONLY ⚠️

This tool is provided for **educational and authorized security testing purposes only**.
Usage of this tool against any system without explicit permission is illegal and unethical.
The authors accept no liability for misuse. This tool is provided as-is without warranty of any kind. Use at your own risk.

## Overview

This proof-of-concept (PoC) script demonstrates security vulnerabilities arising when the Docker socket (`/var/run/docker.sock`) is mounted inside a container. It interacts **directly with the Docker API via HTTP requests to the Unix socket**, showcasing container escape techniques without relying on the Docker CLI client.

This version incorporates improvements based on code review, including more robust scripting practices, better error handling, and enhanced clarity for educational purposes.

## Prerequisites

-   Container with the Docker socket mounted (e.g., `-v /var/run/docker.sock:/var/run/docker.sock`).
-   Basic shell access within that container.
-   `curl`: Used for making HTTP requests to the Docker API socket. The script will attempt to install it if missing via common package managers (`apt-get`, `apk`, `yum`, `dnf`).
-   `jq`: Used for parsing JSON responses from the Docker API. The script will attempt to install it if missing.

If automatic installation fails, these tools must be installed manually.

## Technical Background

The Docker daemon exposes a powerful HTTP API, typically accessible via a Unix socket at `/var/run/docker.sock` by default. This API allows for complete control over Docker, including creating, starting, inspecting, and managing containers, images, volumes, and networks with highly privileged configurations. This PoC leverages direct API calls using `curl --unix-socket` to demonstrate various container escape scenarios.

## Features (Escape Methods Demonstrated)

The script provides an interactive menu to choose from several escape techniques:

1.  **Basic Privileged Container Escape**: Creates a new privileged container that bind-mounts the host's entire filesystem (`/`) and uses `chroot` to gain apparent root access on the host.
2.  **Docker Daemon Configuration Exploit**: Copies a crafted `daemon.json` to the host's Docker configuration directory. If the Docker daemon on the host is restarted, this malicious configuration (e.g., defining a custom runtime that executes arbitrary commands) could be leveraged.
3.  **Custom Capabilities Escape**: Launches a container with powerful Linux capabilities (e.g., `SYS_ADMIN`, `DAC_OVERRIDE`) and minimal security restrictions (`apparmor=unconfined`, `seccomp=unconfined`) to attempt privileged operations like mounting the host filesystem.
4.  **Host Network Namespace Escape**: Deploys a container configured to use the host's network namespace (`NetworkMode: "host"`). The PoC starts a `socat` listener on a port accessible via the host's network interfaces, simulating a backdoor.
5.  **Direct Command Execution on Host (via Privileged Container)**: Creates a privileged container, mounts the host's root filesystem, and executes a script via `chroot` into the host's context, demonstrating command execution as root on the host.
6.  **Container Image Build: COPY from Controlled Context**: Demonstrates using the Docker build API (`/build`) to create an image. A Dockerfile `COPY` instruction is used to include a file from a build context prepared by the script. This method highlights how an attacker, if able to control the build context content (e.g., by staging sensitive host files into it), could exfiltrate data by embedding it into an image.
7.  **Volume Mount Abuse to Access Host Paths**: Creates a container that directly bind-mounts sensitive host files or directories (e.g., `/etc/shadow`, `/`) into the container in read-only mode to exfiltrate their content.
8.  **Host PID Namespace Exploitation**: Launches a container within the host's PID namespace (`PidMode: "host"`), allowing it to see and potentially interact with all processes running on the host (often requires `Privileged: true` for meaningful interaction).
9.  **Create Privileged Exec Session via API**: Creates a long-running, non-privileged container, then uses the Docker exec API (`/containers/{id}/exec` and `/exec/{id}/start`) to start a *new, privileged* command execution session *within that existing container*, demonstrating privilege escalation within the container context to potentially break out.
10. **Full System Compromise (Persistent Privileged Container)**: Deploys a highly privileged container with host PID and network namespaces, root filesystem bind-mounted, and an `always` restart policy. This simulates establishing persistent, privileged access to the host.

## Usage

1.  Ensure you are in an **authorized testing environment** where you have explicit permission to test such vulnerabilities.
2.  Transfer the `docker_socket_api_escape.sh` script into the target container that has the Docker socket mounted.
3.  Make the script executable: `chmod +x docker_socket_api_escape.sh`
4.  Run the script: `./docker_socket_api_escape.sh`
5.  The script will check for `curl` and `jq` and attempt to install them if necessary.
6.  Follow the on-screen menu to select an escape method.
7.  **Cleanup**: Some methods (4 and 10) create persistent containers. The script will output manual `curl` commands to clean them up. Alternatively, you can use the `--cleanup-id` flag:
    `./docker_socket_api_escape.sh --cleanup-id <CONTAINER_ID_TO_REMOVE>`

## Technical Implementation Details

-   **Direct API Calls**: Uses `curl --unix-socket ${DOCKER_SOCKET_PATH}` to send HTTP requests directly to the Docker API.
-   **JSON Payloads**: Constructs JSON payloads for API endpoints like `/containers/create`, `/containers/{id}/start`, `/build`, etc. Heredocs are used for readability.
-   **`jq` for Parsing**: Relies on `jq` for reliably parsing JSON responses from the API (e.g., extracting container IDs).
-   **Helper Functions**: Common Docker operations (create, start, logs, remove, build) are encapsulated in shell functions to improve script structure and reduce redundancy.
-   **Error Handling**: Basic checks for `curl` failures and Docker API error messages are implemented.
-   **Logging**: Provides `log_info`, `log_success`, `log_error`, and `log_warn` messages to track script execution.

Key API endpoints leveraged include:
-   `/images/create`
-   `/containers/create`
-   `/containers/{id}/start`
-   `/containers/{id}/stop`
-   `/containers/{id}/logs`
-   `/containers/{id}/exec` (to create an exec instance)
-   `/exec/{id}/start` (to run the exec instance)
-   `/containers/{id}` (DELETE method for removal)
-   `/images/{name}` (DELETE method for removal)
-   `/build`

## Sample Output (Illustrative)