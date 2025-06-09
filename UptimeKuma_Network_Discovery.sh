#!/bin/bash

# Uptime Kuma Network Discovery Script
# Discovers devices on local subnet and generates Uptime Kuma JSON configuration

set -euo pipefail

# Configuration
SUBNET="${1:-192.168.1.0/24}"
OUTPUT_FILE="${2:-uptime_kuma_config.json}"
UPTIME_KUMA_VERSION="1.23.16"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check required tools
check_dependencies() {
    local missing_tools=()
    
    for tool in nmap ping jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check for ip command (modern replacement for arp)
    if ! command -v "ip" &> /dev/null; then
        missing_tools+=("ip")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        echo "Please install them using:"
        echo "  Ubuntu/Debian: sudo apt-get install nmap iputils-ping iproute2 jq"
        echo "  CentOS/RHEL: sudo yum install nmap iputils iproute jq"
        echo "  Arch: sudo pacman -S nmap iputils iproute2 jq"
        exit 1
    fi
}

# Discover devices on the network
discover_devices() {
    log "Discovering devices on subnet $SUBNET..."
    
    # Use nmap for comprehensive discovery
    nmap -sn "$SUBNET" | grep -E "Nmap scan report|MAC Address" > "$TEMP_DIR/nmap_scan.txt" 2>/dev/null || true
    
    # Parse nmap results
    local current_ip=""
    local devices=()
    
    while IFS= read -r line; do
        if [[ $line =~ Nmap\ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
            current_ip="${BASH_REMATCH[1]}"
        elif [[ $line =~ MAC\ Address:\ ([0-9A-Fa-f:]{17})\ \((.+)\) ]] && [[ -n $current_ip ]]; then
            local mac="${BASH_REMATCH[1]}"
            local vendor="${BASH_REMATCH[2]}"
            devices+=("$current_ip|$mac|$vendor")
            current_ip=""
        elif [[ $line =~ Nmap\ scan\ report\ for\ .+\ \(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\) ]]; then
            current_ip="${BASH_REMATCH[1]}"
        fi
    done < "$TEMP_DIR/nmap_scan.txt"
    
    # Add devices without MAC (like localhost)
    nmap -sn "$SUBNET" 2>/dev/null | grep -oE '([0-9]+\.){3}[0-9]+' | sort -u > "$TEMP_DIR/all_ips.txt"
    
    # Combine results
    printf '%s\n' "${devices[@]}" > "$TEMP_DIR/devices_with_mac.txt" 2>/dev/null || touch "$TEMP_DIR/devices_with_mac.txt"
    
    log "Found $(wc -l < "$TEMP_DIR/all_ips.txt") active devices"
}

# Get device hostname
get_hostname() {
    local ip=$1
    local hostname
    
    # Try multiple methods to get hostname
    hostname=$(nslookup "$ip" 2>/dev/null | grep -oP 'name = \K[^.]+' | head -1 || echo "")
    
    if [[ -z $hostname ]]; then
        hostname=$(ping -c 1 -W 1 "$ip" 2>/dev/null | grep -oP 'PING \K[^ ]+' | head -1 || echo "")
    fi
    
    if [[ -z $hostname ]] || [[ $hostname == "$ip" ]]; then
        # Try to get from ARP table using ip command (modern replacement for arp)
        hostname=$(ip neigh show "$ip" 2>/dev/null | awk '{print $1}' | head -1 || echo "")
    fi
    
    # Try getent hosts as another option
    if [[ -z $hostname ]] || [[ $hostname == "$ip" ]]; then
        hostname=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -1 || echo "")
    fi
    
    # Fallback to IP-based name
    if [[ -z $hostname ]] || [[ $hostname == "$ip" ]]; then
        hostname="Device-${ip##*.}"
    fi
    
    echo "$hostname"
}

# Detect open ports and services
detect_services() {
    local ip=$1
    local services=()
    
    # Quick port scan for common services
    local common_ports="22,23,25,53,80,110,143,443,993,995,3389,5432,3306,6379,27017"
    local open_ports
    
    open_ports=$(nmap -p "$common_ports" --open -T4 "$ip" 2>/dev/null | grep -oP '^\d+(?=/tcp\s+open)' || echo "")
    
    if [[ -n $open_ports ]]; then
        while IFS= read -r port; do
            case $port in
                22) services+=("SSH:$port") ;;
                23) services+=("Telnet:$port") ;;
                25) services+=("SMTP:$port") ;;
                53) services+=("DNS:$port") ;;
                80) services+=("HTTP:$port") ;;
                110) services+=("POP3:$port") ;;
                143) services+=("IMAP:$port") ;;
                443) services+=("HTTPS:$port") ;;
                993) services+=("IMAPS:$port") ;;
                995) services+=("POP3S:$port") ;;
                3389) services+=("RDP:$port") ;;
                5432) services+=("PostgreSQL:$port") ;;
                3306) services+=("MySQL:$port") ;;
                6379) services+=("Redis:$port") ;;
                27017) services+=("MongoDB:$port") ;;
                *) services+=("Unknown:$port") ;;
            esac
        done <<< "$open_ports"
    fi
    
    printf '%s\n' "${services[@]}"
}

# Generate monitor entry
generate_monitor() {
    local id=$1
    local ip=$2
    local hostname=$3
    local service_info=$4
    
    local monitor_type="ping"
    local port="null"
    local url_path=""
    local name="$hostname"
    
    # Parse service info
    if [[ -n $service_info ]]; then
        local service_name="${service_info%%:*}"
        local service_port="${service_info##*:}"
        
        case $service_name in
            "HTTP")
                monitor_type="http"
                port="$service_port"
                url_path="http://$ip"
                name="$hostname (HTTP)"
                ;;
            "HTTPS")
                monitor_type="http"
                port="$service_port"
                url_path="https://$ip"
                name="$hostname (HTTPS)"
                ;;
            "SSH"|"Telnet"|"DNS"|"SMTP"|"POP3"|"IMAP"|"RDP"|"PostgreSQL"|"MySQL"|"Redis"|"MongoDB")
                monitor_type="port"
                port="$service_port"
                name="$hostname ($service_name)"
                ;;
        esac
    fi
    
    cat << EOF
        {
            "id": $id,
            "name": "$name",
            "description": null,
            "pathName": "$name",
            "parent": null,
            "childrenIDs": [],
            "url": "$url_path",
            "method": "GET",
            "hostname": "$ip",
            "port": $port,
            "maxretries": 0,
            "weight": 2000,
            "active": true,
            "forceInactive": false,
            "type": "$monitor_type",
            "timeout": 48,
            "interval": 60,
            "retryInterval": 60,
            "resendInterval": 0,
            "keyword": null,
            "invertKeyword": false,
            "expiryNotification": false,
            "ignoreTls": false,
            "upsideDown": false,
            "packetSize": 56,
            "maxredirects": 10,
            "accepted_statuscodes": ["200-299"],
            "dns_resolve_type": "A",
            "dns_resolve_server": "1.1.1.1",
            "dns_last_result": null,
            "docker_container": "",
            "docker_host": null,
            "proxyId": null,
            "notificationIDList": {},
            "tags": [],
            "maintenance": false,
            "mqttTopic": "",
            "mqttSuccessMessage": "",
            "databaseQuery": null,
            "authMethod": null,
            "grpcUrl": null,
            "grpcProtobuf": null,
            "grpcMethod": null,
            "grpcServiceName": null,
            "grpcEnableTls": false,
            "radiusCalledStationId": null,
            "radiusCallingStationId": null,
            "game": null,
            "gamedigGivenPortOnly": true,
            "httpBodyEncoding": null,
            "jsonPath": null,
            "expectedValue": null,
            "kafkaProducerTopic": null,
            "kafkaProducerBrokers": [],
            "kafkaProducerSsl": false,
            "kafkaProducerAllowAutoTopicCreation": false,
            "kafkaProducerMessage": null,
            "screenshot": null,
            "headers": null,
            "body": null,
            "grpcBody": null,
            "grpcMetadata": null,
            "basic_auth_user": null,
            "basic_auth_pass": null,
            "oauth_client_id": null,
            "oauth_client_secret": null,
            "oauth_token_url": null,
            "oauth_scopes": null,
            "oauth_auth_method": "client_secret_basic",
            "pushToken": null,
            "databaseConnectionString": null,
            "radiusUsername": null,
            "radiusPassword": null,
            "radiusSecret": null,
            "mqttUsername": "",
            "mqttPassword": "",
            "authWorkstation": null,
            "authDomain": null,
            "tlsCa": null,
            "tlsCert": null,
            "tlsKey": null,
            "kafkaProducerSaslOptions": {
                "mechanism": "None"
            },
            "includeSensitiveData": true
        }
EOF
}

# Main function
main() {
    log "Starting Uptime Kuma network discovery for subnet $SUBNET"
    
    check_dependencies
    discover_devices
    
    # Start building JSON
    echo "Generating Uptime Kuma configuration..."
    
    {
        echo "{"
        echo "    \"version\": \"$UPTIME_KUMA_VERSION\","
        echo "    \"notificationList\": [],"
        echo "    \"monitorList\": ["
    } > "$OUTPUT_FILE"
    
    local monitor_id=1
    local first_entry=true
    
    while IFS= read -r ip; do
        if [[ -z $ip ]]; then continue; fi
        
        log "Processing device: $ip"
        
        local hostname
        hostname=$(get_hostname "$ip")
        
        local services
        services=$(detect_services "$ip")
        
        if [[ -z $services ]]; then
            # Add ping monitor for devices without detected services
            if [[ $first_entry == true ]]; then
                first_entry=false
            else
                echo "," >> "$OUTPUT_FILE"
            fi
            generate_monitor "$monitor_id" "$ip" "$hostname" "" >> "$OUTPUT_FILE"
            ((monitor_id++))
        else
            # Add monitors for each detected service
            while IFS= read -r service; do
                if [[ -n $service ]]; then
                    if [[ $first_entry == true ]]; then
                        first_entry=false
                    else
                        echo "," >> "$OUTPUT_FILE"
                    fi
                    generate_monitor "$monitor_id" "$ip" "$hostname" "$service" >> "$OUTPUT_FILE"
                    ((monitor_id++))
                fi
            done <<< "$services"
            
            # Also add a ping monitor for the device itself
            if [[ $first_entry == true ]]; then
                first_entry=false
            else
                echo "," >> "$OUTPUT_FILE"
            fi
            generate_monitor "$monitor_id" "$ip" "$hostname" "" >> "$OUTPUT_FILE"
            ((monitor_id++))
        fi
    done < "$TEMP_DIR/all_ips.txt"
    
    # Close JSON
    {
        echo ""
        echo "    ]"
        echo "}"
    } >> "$OUTPUT_FILE"
    
    # Validate JSON
    if jq empty "$OUTPUT_FILE" 2>/dev/null; then
        success "Generated Uptime Kuma configuration: $OUTPUT_FILE"
        success "Total monitors created: $((monitor_id - 1))"
        log "You can now import this file into Uptime Kuma"
    else
        error "Generated JSON is invalid. Please check the output file."
        exit 1
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [SUBNET] [OUTPUT_FILE]"
    echo ""
    echo "Arguments:"
    echo "  SUBNET      Network subnet to scan (default: 192.168.1.0/24)"
    echo "  OUTPUT_FILE Output JSON file (default: uptime_kuma_config.json)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Scan 192.168.1.0/24"
    echo "  $0 10.0.0.0/24                      # Scan 10.0.0.0/24"
    echo "  $0 192.168.1.0/24 my_monitors.json # Custom output file"
    echo ""
    echo "Required tools: nmap, ping, ip, jq"
}

# Handle command line arguments
case "${1:-}" in
    -h|--help)
        show_usage
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
