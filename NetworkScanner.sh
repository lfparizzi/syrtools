#!/bin/bash
# V3 (SMBv1, Assinatura e SNMP)
# Script para escanear ranges de IP e realizar testes adicionais modulares

# modo de uso: ./NetworkScanner.sh <ip/range/wordlist> [--force]

# Por padrão ele vai fazer um pingsweap e vai trabalhar apenas nos IPs que responderem ao ping, para forçar o scan de todos os IPs dos ranges, utilizar a opção "--force"

if [ "$#" -lt 1 ]; then
    echo "Uso: $0 <wordlist.txt> [--force]"
    exit 1
fi

wordlist="$1"
force_all_ips=false

if [ "$2" == "--force" ]; then
    force_all_ips=true
fi

if [ ! -f "$wordlist" ]; then
    echo "Arquivo '$wordlist' não encontrado!"
    exit 1
fi

declare -a results
declare -A ip_files_map

while read -r range; do
    [[ -z "$range" || "$range" =~ ^# ]] && continue
    range=$(echo "$range" | xargs)
    file_name=$(echo "$range" | sed 's/\//_/')
    output_file="ips_ativos_${file_name}.txt"

    echo "Escaneando o range: $range"

    if [ "$force_all_ips" = true ]; then
        echo "Modo --force ativado. Gerando todos os IPs do range $range..."
        nmap -n -sL "$range" | awk '/Nmap scan report for/ { print $NF }' > "$output_file"
    else
        scan_output=$(nmap -sn -n --min-rate 2000 "$range" | grep "Nmap scan report for" | cut -d " " -f 5)
        echo "$scan_output" > "$output_file"
    fi

    if [ ! -s "$output_file" ]; then
        count=0
        echo "Nenhum IP encontrado no range: $range"
    else
        count=$(wc -l < "$output_file")
        echo "Resultado salvo em: $output_file - Hosts considerados: $count"
    fi

    results+=("$range|$count")
    ip_files_map["$range"]="$output_file"
done < "$wordlist"

echo -e "\nResumo dos resultados:"
printf "%-25s %s\n" "Range" "Hosts considerados"
printf "%-25s %s\n" "-------------------------" "------------------"
for item in "${results[@]}"; do
    IFS='|' read -r r count <<< "$item"
    printf "%-25s %s\n" "$r" "$count"
done

echo ""
echo "Deseja realizar escaneamento nos IPs?"
echo "1) Não Escanear"
echo "2) Scan Básico (nmap -sS -sV)"
echo "3) Scan All Ports (nmap -sS -sV -p-)"
echo "4) Scan vulnerabilidades SMB (SMBv1 e SMBv2)"
echo "5) Scan SNMP (porta UDP 161 + snmpwalk)"
read -rp "Escolha uma opção [1-5]: " scan_option

case "$scan_option" in
    1)
        echo "Encerrando sem escanear."
        exit 0
        ;;
    2)
        scan_args="-sS -sV --min-rate 2000"
        ;;
    3)
        scan_args="-sS -sV -p- --min-rate 2000"
        ;;
    4)
        echo -e "\nIniciando todos os scans SMB (aguarde)...\n"

        smb_v1_all="todos_smbv1_ativos.txt"
        smb_v2_all="todos_smbv2_assinatura_nao_forcada.txt"

        > "$smb_v1_all"
        > "$smb_v2_all"

        for range in "${!ip_files_map[@]}"; do
            ip_file="${ip_files_map[$range]}"
            [ ! -s "$ip_file" ] && continue

            smb_v1_output=$(mktemp)
            nmap -n --script smb-protocols -p 445 --min-rate 2000 -iL "$ip_file" -oN "$smb_v1_output"
            awk '/Nmap scan report for/ { ip = $NF; gsub(/[()]/, "", ip) } /NT LM 0.12 \(SMBv1\)/ { print ip }' "$smb_v1_output" >> "$smb_v1_all"
            rm -f "$smb_v1_output"

            smb_v2_output=$(mktemp)
            nmap -sS --script smb2-security* -p 445 --min-rate 2000 -iL "$ip_file" -oN "$smb_v2_output"
            grep 'enabled but not required' -B 10 "$smb_v2_output" | grep 'Nmap scan report for' | awk '{print $5}' | sed 's/[()]//g' >> "$smb_v2_all"
            rm -f "$smb_v2_output"
        done

        echo -e "\n==========================="
        echo "      RESULTADOS FINAIS"
        echo "==========================="

        echo "IPs com SMBv1 ativo:"
        [ -s "$smb_v1_all" ] && sort -u "$smb_v1_all" || echo "Nenhum IP com SMBv1 ativo encontrado."

        echo -e "\nIPs com SMBv2 com assinatura não forçada:"
        [ -s "$smb_v2_all" ] && sort -u "$smb_v2_all" || echo "Nenhum IP com SMBv2 e assinatura não forçada."

        echo -e "\nOs resultados salvos em:"
        echo "  - $smb_v1_all"
        echo "  - $smb_v2_all"
        exit 0
        ;;
    5)
        echo -e "\nIniciando scan SNMP (porta 161 UDP)...\n"

        snmp_grep_output="nmap_snmp_scan.txt"
        snmp_ips_found="ips_snmp_ativos.txt"
        snmp_vuln_output="ipsSNMPvuln.txt"

        > "$snmp_grep_output"
        > "$snmp_ips_found"
        > "$snmp_vuln_output"

        for range in "${!ip_files_map[@]}"; do
            ip_file="${ip_files_map[$range]}"
            [ ! -s "$ip_file" ] && continue

            echo "Escaneando SNMP no range $range..."
            nmap -sU -p 161 --min-rate 2000 -iL "$ip_file" -oG - \
                | grep "161/open/udp" | awk '{print $2}' >> "$snmp_ips_found"
        done

        if [ ! -s "$snmp_ips_found" ]; then
            echo "Nenhum IP com SNMP ativo encontrado."
            exit 0
        fi

        echo "Executando snmpwalk nos IPs encontrados..."

        while IFS= read -r ip; do
            echo "Testando $ip com snmpwalk..."
            RESPONSE=$(timeout 1 snmpwalk -c public -v1 -t 1 "$ip" iso.3.6.1.2.1.1.1.0 2>/dev/null)
            [ -n "$RESPONSE" ] && echo "$ip" | tee -a "$snmp_vuln_output"
        done < "$snmp_ips_found"

        echo -e "\nScan SNMP concluído!"
        echo "IPs com SNMP e resposta via community 'public' salvos em: $snmp_vuln_output"
        exit 0
        ;;
esac

echo -e "\nIniciando escaneamento de portas...\n"
for range in "${!ip_files_map[@]}"; do
    ip_file="${ip_files_map[$range]}"
    [ ! -s "$ip_file" ] && continue

    range_clean="${range//\//_}"
    output_scan_file="scan_${range_clean}.txt"
    echo "Escaneando portas em $range..."
    nmap $scan_args -iL "$ip_file" -oN "$output_scan_file"
    echo "Resultado salvo em: $output_scan_file"
    echo ""
done
