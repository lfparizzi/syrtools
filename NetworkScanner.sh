#!/bin/bash
# V3.1 (SMBv1, scans, Assinatura SMB e SNMP)
# Script para escanear ranges de IP e realizar testes adicionais modulares
# Uso: ./NetworkScannerV2.sh <ip/range/wordlist> [--force]

# Por padrão ele vai fazer um pingsweap e vai trabalhar apenas nos IPs que responderem ao ping, para forçar os testes em todos os IPs dos ranges, utilizar a opção "--force"

if [ "$#" -lt 1 ]; then
    echo "Uso: $0 <ip|range|wordlist.txt> [--force]"
    exit 1
fi

input="$1"
force_all_ips=false

if [ "$2" == "--force" ]; then
    force_all_ips=true
fi

# Se for um arquivo, trata como wordlist. Caso contrário, trata como range único.
if [ -f "$input" ]; then
    mapfile -t ranges < "$input"
else
    ranges=("$input")
fi

declare -a results
declare -A ip_files_map

for range in "${ranges[@]}"; do
    [[ -z "$range" || "$range" =~ ^# ]] && continue
    range=$(echo "$range" | xargs)
    file_name=$(echo "$range" | sed 's/\//_/g')
    output_file="ips_ativos_${file_name}.txt"

    echo "Escaneando o range: $range"

    if [ "$force_all_ips" = true ]; then
        echo "Modo --force ativado. Gerando todos os IPs do range $range..."
        nmap -n -sL "$range" | awk '/Nmap scan report for/ { print $NF }' > "$output_file"
    else
        scan_output=$(nmap -sn -n --min-rate 2000 "$range" | grep "Nmap scan report for" | cut -d " " -f 5)
        echo "$scan_output" | sed '/^$/d' > "$output_file"
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
done

echo -e "\nResumo dos resultados:"
printf "%-25s %s\n" "Range" "Hosts considerados"
printf "%-25s %s\n" "-------------------------" "------------------"
for item in "${results[@]}"; do
    IFS='|' read -r r count <<< "$item"
    printf "%-25s %s\n" "$r" "$count"
done

echo ""
echo "Escolha uma das opções para escanear:"
echo "1) Não Escanear"
echo "2) Scan Básico (nmap -sS -sV)"
echo "3) Scan All Ports (nmap -sS -sV -p-)"
echo "4) Scan vulnerabilidades SMB (SMBv1 e Signing False)"
echo "5) Scan vulnerabilidades SNMP (Versão 1 e community public)"
echo "6) Null Access Scan"
read -rp "Escolha uma opção [1-6]: " scan_option

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

        smb_v1_all="Vulns_smbv1_ativos.txt"
        smb_v2_all="Vulns_smbv2_assinatura_nao_forcada.txt"

        > "$smb_v1_all"
        > "$smb_v2_all"

        for range in "${!ip_files_map[@]}"; do
            ip_file="${ip_files_map[$range]}"
            [ ! -s "$ip_file" ] && continue

            # SMBv1
            smb_v1_output=$(mktemp)
            nmap -n --script smb-protocols -p 445 --min-rate 2000 -iL "$ip_file" -oN "$smb_v1_output"
            awk '/Nmap scan report for/ { ip = $NF; gsub(/[()]/, "", ip) } /NT LM 0.12 \(SMBv1\)/ { print ip }' "$smb_v1_output" >> "$smb_v1_all"
            rm -f "$smb_v1_output"

            # SMBv2
            smb_v2_output=$(mktemp)
            nmap -sS --script smb2-security* -p 445 --min-rate 2000 -iL "$ip_file" -oN "$smb_v2_output"
            grep 'enabled but not required' -B 10 "$smb_v2_output" \
              | grep 'Nmap scan report for' \
              | awk '{print $5}' | sed 's/[()]//g' >> "$smb_v2_all"
            rm -f "$smb_v2_output"
        done

        echo ""
        echo -e "\n==========================="
        echo "      RESULTADOS FINAIS"
        echo "==========================="
        echo ""

        echo "IPs com SMBv1 ativo:"
        [ -s "$smb_v1_all" ] && sort -u "$smb_v1_all" || echo "Nenhum IP com SMBv1 ativo encontrado."

        echo -e "\nIPs com SMBv2 com assinatura não forçada:"
        [ -s "$smb_v2_all" ] && sort -u "$smb_v2_all" || echo "Nenhum IP com SMBv2 e assinatura não forçada."

        echo -e "\nOs resultados foram salvos em:"
        echo "  - $smb_v1_all"
        echo "  - $smb_v2_all"
        exit 0
        ;;
    5)
        echo -e "\nIniciando scan SNMP (UDP 161 + snmpwalk público)...\n"

        snmp_ips="ips_snmp_ativos.txt"
        snmp_output="nmap_snmp_scan.txt"
        snmp_vuln="Vulns_SNMP_inseguro.txt"

        > "$snmp_ips"
        > "$snmp_output"
        > "$snmp_vuln"

        for range in "${!ip_files_map[@]}"; do
            ip_file="${ip_files_map[$range]}"
            [ ! -s "$ip_file" ] && continue

            echo "Verificando SNMP em IPs do range $range..."
            nmap -sU -p 161 --min-rate 2000 -iL "$ip_file" -oG - >> "$snmp_output"
        done

        grep "161/open/udp" "$snmp_output" | awk '{print $2}' >> "$snmp_ips"

        if [ ! -s "$snmp_ips" ]; then
            echo "Nenhum IP com SNMP ativo foi encontrado."
            exit 0
        fi

        echo -e "\nExecutando snmpwalk nos IPs com SNMP ativo...\n"
        while IFS= read -r ip; do
            echo "Testando $ip..."
            RESPONSE=$(timeout 1 snmpwalk -c public -v1 -t 1 "$ip" iso.3.6.1.2.1.1.1.0 2>/dev/null)
            if [ -n "$RESPONSE" ]; then
                echo "$ip" | tee -a "$snmp_vuln"
            fi
        done < "$snmp_ips"

        echo ""
        echo "Scan SNMP concluído!"
        echo "IPs com resposta ao snmpwalk público salvos em: $snmp_vuln"
        ;;
     6)
        echo -e "\nIniciando enumeração SMB (null sessions com netexec)...\n"

        # Arquivos temporários
        smb_445_ips="ips_445_ativos.txt"
        null_sessions="null-sessions.txt"
        netexec_output="netexec_smb_output.txt"
        shares_output="nullsession_shares.txt"
        resumo_output="resumo_null_shares.txt"

        # Limpando arquivos antigos
        > "$smb_445_ips"
        > "$null_sessions"
        > "$netexec_output"
        > "$shares_output"
        > "$resumo_output"

        # Fase 1: IPs com porta 445 aberta
        echo "[*] Fase 1: Verificando IPs com porta 445 aberta..."
        for range in "${!ip_files_map[@]}"; do
            ip_file="${ip_files_map[$range]}"
            [ ! -s "$ip_file" ] && continue

            echo "Escaneando porta 445 em IPs do range $range..."
            nmap -p 445 --open -n --min-rate 3000 -iL "$ip_file" -oG - | awk '/445\/open/ {print $2}' >> "$smb_445_ips"
        done

        if [ ! -s "$smb_445_ips" ]; then
            echo "Nenhum IP com porta 445 aberta foi encontrado."
            exit 0
        fi

        sort -u "$smb_445_ips" -o "$smb_445_ips"
        echo "[*] IPs com porta 445 aberta salvos em: $smb_445_ips"

        # Fase 2: Rodando netexec para autenticação null session
        echo "[*] Fase 2: Rodando netexec para autenticação null session..."
        netexec smb "$smb_445_ips" -u '' -p '' | tee "$netexec_output"

        # Fase 3: Filtrando hosts com null session
        echo "[*] Fase 3: Filtrando hosts com null session..."
        grep "\[+\]" "$netexec_output" | tr -s ' ' | cut -d ' ' -f2 | sort -u > "$null_sessions"

        if [ ! -s "$null_sessions" ]; then
            echo "Nenhum host com null session foi encontrado."
            exit 0
        fi

        echo "[*] IPs com null session salvos em: $null_sessions"

        # Fase 4: Enumerando shares acessíveis via null session
        echo "[*] Fase 4: Enumerando shares acessíveis via null session..."
        netexec smb "$null_sessions" -u '' -p '' --shares | tee "$shares_output"

        # Padroniza múltiplos espaços
        tr -s ' ' < "$shares_output" > "$shares_output.tmp" && mv "$shares_output.tmp" "$shares_output"

        # Fase 5: Gerando tabela de resumo usando diretamente null_sessions.txt
        echo "[*] Fase 5: Gerando tabela de resumo..."
        > "$resumo_output"
        echo -e "Resumo dos resultados:" >> "$resumo_output"
        printf "%-25s %s\n" "IP Null Access" >> "$resumo_output"
        printf "%-25s %s\n" "-------------------------" >> "$resumo_output"

        while read -r ip; do
            # Extrai todas as shares do shares_output associadas ao IP
            shares=$(grep "^$ip " "$shares_output" | cut -d ' ' -f2- | tr '\n' ',' | sed 's/,$//')
            printf "%-25s %s\n" "$ip" "$shares" >> "$resumo_output"
        done < "$null_sessions"

        # Mostra resumo
        echo ""
        cat "$resumo_output"
        echo ""
        echo "[*] Resumo também salvo em: $resumo_output"
        echo "[*] Resultado completo do netexec salvo em: $shares_output"
        exit 0
        ;;

    *)
        echo "Opção inválida."
        exit 1
        ;;
esac

# Executa scans de portas para opções 2 ou 3
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
