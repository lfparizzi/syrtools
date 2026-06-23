#!/bin/bash
# V5.0 - Completo, Modular e com Execução Sequencial Múltipla
# Uso: ./NetworkScannerV5.sh <ip/range/wordlist> [--force] [--ping-only]

set -e # Para o script se houver erros bizarros de sintaxe

if [ "$#" -lt 1 ]; then
    echo "Uso: $0 <ip|range|wordlist.txt> [--force] [--ping-only]"
    exit 1
fi

# --- Configurações Iniciais e Estrutura de Pastas ---
INPUT="$1"
FORCE_ALL_IPS=false
PING_ARGS="-sn"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="scan_results_${TIMESTAMP}"

mkdir -p "$OUTPUT_DIR"

# Limpeza de arquivos temporários caso o script seja interrompimento (Ctrl+C)
cleanup() {
    echo -e "\n[*] Script finalizado. Resultados salvos na pasta: $OUTPUT_DIR"
}
trap cleanup EXIT

# --- Parsing de Argumentos de Inicialização ---
for arg in "$@"; do
    if [ "$arg" == "--force" ]; then FORCE_ALL_IPS=true; fi
    if [ "$arg" == "--ping-only" ]; then
        PING_ARGS="-sn -PE"
        echo "[!] Modo --ping-only ativado: Usando apenas ICMP Echo Request."
    fi
done

if [ -f "$INPUT" ]; then
    mapfile -t RANGES < "$INPUT"
else
    RANGES=("$INPUT")
fi

declare -A IP_FILES_MAP

# --- Módulos de Funções ---

exec_host_discovery() {
    local range="$1"
    [[ -z "$range" || "$range" =~ ^# ]] && return
    range=$(echo "$range" | xargs)
    local clean_name=$(echo "$range" | sed 's/\//_/g')
    local out_file="${OUTPUT_DIR}/ips_ativos_${clean_name}.txt"
    
    echo "[*] Escaneando o range: $range"
    
    if [ "$FORCE_ALL_IPS" = true ]; then
        nmap -n -sL "$range" | awk '/Nmap scan report for/ { print $NF }' > "$out_file"
    else
        sudo nmap $PING_ARGS -n --min-rate 2000 "$range" | awk '/Nmap scan report for/ {print $5}' | sed 's/[()]//g' > "$out_file"
    fi
    
    local count=$(wc -l < "$out_file")
    echo "[+] Salvo em: $out_file - Hosts ativos: $count"
    IP_FILES_MAP["$range"]="$out_file"
}

scan_portas_generico() {
    local tipo="$1" # "basico" ou "tudo"
    local args="-sS -sV --min-rate 2000"
    [ "$tipo" == "tudo" ] && args="$args -p-"
    
    echo -e "\n=============================================="
    echo "[*] Iniciando Scan de Portas ($tipo)"
    echo "=============================================="
    
    for range in "${!IP_FILES_MAP[@]}"; do
        local ip_file="${IP_FILES_MAP[$range]}"
        [ ! -s "$ip_file" ] && continue
        
        local range_clean="${range//\//_}"
        local out_file="${OUTPUT_DIR}/scan_${tipo}_${range_clean}.txt"
        
        echo "[*] Escaneando alvos do range $range..."
        nmap $args -iL "$ip_file" -oN "$out_file"
        echo "[+] Resultado salvo em: $out_file"
    done
}

scan_smb_vulns() {
    echo -e "\n=============================================="
    echo "[*] Iniciando Identificação de Vulnerabilidades SMB"
    echo "=============================================="
    
    local smb_v1_all="${OUTPUT_DIR}/Vulns_smbv1_ativos.txt"
    local smb_v2_all="${OUTPUT_DIR}/Vulns_smbv2_assinatura_nao_forcada.txt"
    > "$smb_v1_all"
    > "$smb_v2_all"

    for range in "${!IP_FILES_MAP[@]}"; do
        local ip_file="${IP_FILES_MAP[$range]}"
        [ ! -s "$ip_file" ] && continue
        
        # Paraleliza a execução por range para poupar tempo
        (
            local t_v1=$(mktemp)
            local t_v2=$(mktemp)
            
            nmap -n --script smb-protocols -p 445 --min-rate 2000 -iL "$ip_file" -oN "$t_v1" >/dev/null 2>&1
            awk '/Nmap scan report for/ { ip = $NF; gsub(/[()]/, "", ip) } /NT LM 0.12 \(SMBv1\)/ { print ip }' "$t_v1" >> "$smb_v1_all"
            
            nmap -sS --script smb2-security* -p 445 --min-rate 2000 -iL "$ip_file" -oN "$t_v2" >/dev/null 2>&1
            grep 'enabled but not required' -B 10 "$t_v2" | grep 'Nmap scan report for' | awk '{print $5}' | sed 's/[()]//g' >> "$smb_v2_all"
            
            rm -f "$t_v1" "$t_v2"
        ) &
    done
    wait

    echo -e "\n[+] IPs com SMBv1 ativo (Resultados Consolidados):"
    [ -s "$smb_v1_all" ] && sort -u "$smb_v1_all" || echo "Nenhum detectado."
    echo -e "\n[+] IPs com SMBv2 sem assinatura forçada:"
    [ -s "$smb_v2_all" ] && sort -u "$smb_v2_all" || echo "Nenhum detectado."
}

scan_snmp_vulns() {
    echo -e "\n=============================================="
    echo "[*] Iniciando Scan e Enumeração SNMP"
    echo "=============================================="
    
    local snmp_ips="${OUTPUT_DIR}/ips_snmp_ativos.txt"
    local snmp_output="${OUTPUT_DIR}/nmap_snmp_scan.txt"
    local snmp_vuln="${OUTPUT_DIR}/Vulns_SNMP_inseguro.txt"
    > "$snmp_ips"; > "$snmp_output"; > "$snmp_vuln"

    for range in "${!IP_FILES_MAP[@]}"; do
        local ip_file="${IP_FILES_MAP[$range]}"
        [ ! -s "$ip_file" ] && continue
        nmap -sU -p 161 --min-rate 2000 -iL "$ip_file" -oG - >> "$snmp_output"
    done

    grep "161/open/udp" "$snmp_output" | awk '{print $2}' >> "$snmp_ips"

    if [ ! -s "$snmp_ips" ]; then
        echo "[-] Nenhum host com porta UDP 161 aberta foi encontrado."
        return
    fi

    echo "[*] Rodando snmpwalk (comunidade public) nos ativos..."
    while IFS= read -r ip; do
        local response=$(timeout 1 snmpwalk -c public -v1 -t 1 "$ip" iso.3.6.1.2.1.1.1.0 2>/dev/null)
        if [ -n "$response" ]; then
            echo "$ip" | tee -a "$snmp_vuln"
        fi
    done < "$snmp_ips"
}

scan_null_session() {
    echo -e "\n=============================================="
    echo "[*] Iniciando Mapeamento de Null Session (NetExec)"
    echo "=============================================="
    
    local smb_445_ips="${OUTPUT_DIR}/ips_445_ativos.txt"
    local null_sessions="${OUTPUT_DIR}/null-sessions.txt"
    local netexec_output="${OUTPUT_DIR}/netexec_smb_output.txt"
    local shares_output="${OUTPUT_DIR}/nullsession_shares.txt"
    local resumo_output="${OUTPUT_DIR}/resumo_null_shares.txt"
    
    > "$smb_445_ips"; > "$null_sessions"; > "$netexec_output"; > "$shares_output"; > "$resumo_output"

    for range in "${!IP_FILES_MAP[@]}"; do
        local ip_file="${IP_FILES_MAP[$range]}"
        [ ! -s "$ip_file" ] && continue
        nmap -p 445 --open -n --min-rate 3000 -iL "$ip_file" -oG - | awk '/445\/open/ {print $2}' >> "$smb_445_ips"
    done

    if [ ! -s "$smb_445_ips" ]; then
        echo "[-] Nenhuma porta 445 aberta encontrada nos ranges."
        return
    fi

    sort -u "$smb_445_ips" -o "$smb_445_ips"
    
    echo "[*] Validando acessos e coletando shares via NetExec..."
    netexec smb "$smb_445_ips" -u '' -p '' | tee "$netexec_output" >/dev/null 2>&1
    grep "\[+\]" "$netexec_output" | tr -s ' ' | cut -d ' ' -f2 | sort -u > "$null_sessions"

    if [ ! -s "$null_sessions" ]; then
        echo "[-] Nenhuma Null Session válida identificada."
        return
    fi

    netexec smb "$null_sessions" -u '' -p '' --shares | tee "$shares_output" >/dev/null 2>&1
    tr -s ' ' < "$shares_output" > "${shares_output}.tmp" && mv "${shares_output}.tmp" "$shares_output"

    # Montagem do relatório final em tela
    echo -e "\nResumo Null Session:" >> "$resumo_output"
    printf "%-25s %s\n" "IP Null Access" "Shares Disponíveis" >> "$resumo_output"
    printf "%-25s %s\n" "-------------------------" "------------------" >> "$resumo_output"

    while read -r ip; do
        local shares=$(grep "^$ip " "$shares_output" | cut -d ' ' -f2- | tr '\n' ',' | sed 's/,$//')
        printf "%-25s %s\n" "$ip" "$shares" >> "$resumo_output"
    done < "$null_sessions"
    
    cat "$resumo_output"
}

# --- Fluxo de Execução Principal ---

echo "[*] Fase 1: Descoberta de Hosts Ativos"
for r in "${RANGES[@]}"; do
    exec_host_discovery "$r"
done

# Exibição do resumo inicial de escopo
echo -e "\nResumo dos alvos:"
printf "%-25s %s\n" "Range" "Hosts Ativos"
printf "%-25s %s\n" "-------------------------" "------------"
for r in "${!IP_FILES_MAP[@]}"; do
    printf "%-25s %s\n" "$r" "$(wc -l < "${IP_FILES_MAP[$r]}")"
done

# Apresentação do Menu Interativo
echo -e "\nEscolha os modos de teste."
echo "Você pode digitar múltiplas opções separadas por vírgula ou espaço (ex: 2,4,6 ou 2 5):"
echo "1) Sair (Não Escanear)"
echo "2) Scan Básico (nmap -sS -sV)"
echo "3) Scan All Ports (nmap -sS -sV -p-)"
echo "4) Scan vulnerabilidades SMB (SMBv1 e Signing False)"
echo "5) Scan vulnerabilidades SNMP (Versão 1 e community public)"
echo "6) Null Access Scan (NetExec)"
read -rp "Opção(ões): " OPCOES_INPUT

# Normalização do input do usuário (substitui vírgulas por espaços e remove duplicatas)
OPCOES_CLEAN=$(echo "$OPCOES_INPUT" | sed 's/,/ /g' | tr -s ' ')

for opcao in $OPCOES_CLEAN; do
    case "$opcao" in
        1)
            echo "[*] Saindo do script."
            exit 0
            ;;
        2)
            scan_portas_generico "basico"
            ;;
        3)
            scan_portas_generico "tudo"
            ;;
        4)
            scan_smb_vulns
            ;;
        5)
            scan_snmp_vulns
            ;;
        6)
            scan_null_session
            ;;
        *)
            echo "[!] Opção '$opcao' é inválida e será ignorada."
            ;;
    esac
done
