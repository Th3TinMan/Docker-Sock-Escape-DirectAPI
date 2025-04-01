# Docker Socket Container Escape API PoC

## ⚠️ WARNING: EDUCATIONAL PURPOSE ONLY ⚠️

This tool is provided for **educational and authorized security testing purposes only**. 
Usage of this tool against any system without explicit permission is illegal and unethical.

## Overview

This proof-of-concept (PoC) demonstrates the security vulnerability that arises when the Docker socket (`/var/run/docker.sock`) is mounted inside a container. Unlike other examples that use the Docker CLI commands, this PoC interacts directly with the Docker API via HTTP requests to the Unix socket.

The tool provides multiple methods to demonstrate how an attacker with access to the Docker socket could escape container isolation and gain access to the host system.

## Prerequisites

- Container with Docker socket mounted (`/var/run/docker.sock`)
- Basic shell access to the container
- `curl` (script will attempt to install if missing)

## Technical Background

The Docker daemon exposes an HTTP API through a Unix socket at `/var/run/docker.sock`. This API enables full control over Docker, including creating, starting, and managing containers with custom configurations. The PoC leverages direct API calls to demonstrate container escapes without relying on the Docker CLI.

## Features

The PoC demonstrates multiple container escape techniques using direct API calls:

1. **Basic Privileged Container Escape**: Creates a privileged container that mounts the host filesystem
2. **Docker Daemon Configuration Exploit**: Modifies Docker daemon settings 
3. **Custom Capabilities Escape**: Uses SYS_ADMIN capability to break out
4. **Network Namespace Escape**: Deploys container with host network access
5. **Docker API Command Execution**: Runs commands on the host via Docker API
6. **Build Context Exploitation**: Accesses host files during image builds
7. **Volume Mount Abuse**: Accesses sensitive host directories
8. **PID Namespace Exploitation**: Accesses host processes
9. **Exec API Exploitation**: Creates privileged exec sessions
10. **Full System Compromise**: Demonstrates persistence techniques

## Usage

1. Download the script onto a container with the Docker socket mounted
2. Make the script executable: `chmod +x docker_socket_api_escape.sh`
3. Run the script: `./docker_socket_api_escape.sh`
4. Select the desired escape method from the menu

## Technical Implementation

This PoC uses `curl` with the `--unix-socket` option to communicate directly with the Docker API via the Unix socket. It constructs appropriate JSON payloads for container creation, execution, and management.

Key API endpoints used include:
- `/containers/create`: Creates new containers with custom configurations
- `/containers/{id}/start`: Starts containers
- `/containers/{id}/logs`: Retrieves container logs
- `/containers/{id}/exec`: Creates exec instances in running containers
- `/exec/{id}/start`: Starts exec instances
- `/build`: Builds container images

## Sample Output

```
[*] Docker Socket Container Escape - Direct API Version
[*] Starting vulnerability check...
[+] Docker socket found. Container may be vulnerable.

Available escape methods:
1. Basic privileged container escape (mount host filesystem)
2. Docker daemon configuration exploit (API version)
3. Create container with custom capabilities (API version)
...

Select escape method (1-10): 1
[+] Executing basic privileged container escape via API...
[+] Container escape successful. Now running on the host with root privileges.
[+] Hostname: host-machine-name
[+] Host files: [host file listing]
```

## Mitigation Strategies

To protect your systems against Docker socket container escapes:

1. **Never** mount the Docker socket (`/var/run/docker.sock`) into containers unless absolutely necessary
2. If Docker API access is required, implement a secure API proxy with proper access controls
3. Use namespaced secrets and proper authentication for Docker API access
4. Consider socket file permission restrictions when Docker socket access is required
5. Implement proper network isolation for containers
6. Use read-only file systems for containers where possible
7. Apply seccomp, AppArmor, or SELinux profiles to restrict container capabilities
8. Keep Docker and host systems updated with security patches
9. Use container-specific security monitoring tools
10. Consider using container security platforms for defense in depth

## Understanding Docker API Security

The Docker API is a powerful interface that allows complete control over the Docker daemon. Key security considerations when the socket is exposed include:

- The Docker API has no built-in authentication mechanism when accessed via Unix socket
- API access is equivalent to root access on the host in default configurations
- All API endpoints should be considered sensitive from a security perspective
- Unix socket permissions are the primary security boundary for the API

## Further Research

Understanding the Docker API can be valuable for security researchers and administrators. This PoC demonstrates the risks of improper socket exposure and can be extended to test additional API endpoints and security configurations.

## Responsible Disclosure

If you discover vulnerable configurations in production environments, please follow responsible disclosure procedures and inform the system owners before taking any action.

## Disclaimer

The authors of this tool accept no liability for misuse. This tool is provided as-is without warranty of any kind. Use at your own risk and only in authorized environments.

## License

This project is released under the MIT License.