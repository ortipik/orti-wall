#!/bin/bash
#<!-- Copyright (c) 2026 ortipik - Licence MIT (voir fichier LICENSE) -->
#-----------------------------------------------------------------------
# ce script a été élaboré par Ortipik pour OMEGA-server.
# https://kraynux.snake-mackarel.ts.net
#-----------------------------------------------------------------------

# ============================================
# FIREWALL MANAGER - nftables & fail2ban & iptables
# Gestion unifiée des blacklists et honeypots
# ============================================

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

#-----------------------------------------------------------------------
#============ PARTIE A CONFIGURER ======================================
# Configuration
NFT_FAMILY="inet" # nom de la famille de NFTABLE
NFT_TABLE_NAME="myblacklist" # nom de la table de  NFTABLE
NFT_SET="blacklist" # nom de la config de NFTABLE
LOG_FILE="/var/log/firewall-manager.log" # chemin ou seront stockés les logs du firewall-manager
IPTABLES_SAVE="/etc/iptables/iptables.rules" # chemin ou seront stockés les regles IPTABLES
DEFAULT_BLOCKLIST_FILE="/etc/blocklist.txt" # chemin du fichier texte ou seront stockés les IPs (à créer)
FAIL2BAN_JAILS=("honeypot" "aggressive" "agents" "honeypot" "ipv6" "critical-ipv6" "scanner" "404" "sshd" "ftp" "recidive" "web" "manual-blacklist") # le nom des jails de fail2ban que vous avez créées et que vous voulez incorporer dans orti-wall (ici ce sont des exemples)
#==========FIN DE LA PARTIE A CONFIGURER ===============================
#-----------------------------------------------------------------------

# ============================================
# FONCTIONS UTILITAIRES
# ============================================

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" | tee -a "$LOG_FILE"
}

validate_ip() {
    local ip="$1"

    if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        if ((octet < 0 || octet > 255)); then
            return 1
        fi
    done

    return 0
}

pause() {
    echo ""
    read -r -p "Appuyez sur Entrée pour continuer..."
}

clear_screen() {
    clear
    echo -e "${CYAN}▶️ ============================================================= ▶️${NC}"
    echo -e "${CYAN}     FIREWALL MANAGER - v2.0 nftables-fail2ban-iptables       ${NC}"
    echo -e "${CYAN}▶️ ============================================================= ▶️${NC}"
    echo ""
}

save_iptables() {
    sudo mkdir -p /etc/iptables
    sudo iptables-save | sudo tee "$IPTABLES_SAVE" > /dev/null
    log "Règles iptables sauvegardées"
}

save_blacklist_persistent() {
    sudo nft list table "$NFT_FAMILY" "$NFT_TABLE_NAME" | sudo tee /etc/nftables-blacklist.conf > /dev/null
    log "Blacklist sauvegardée dans /etc/nftables-blacklist.conf"
}

# ============================================
# GESTION NFTABLES
# ============================================

init_nftables() {
    if ! sudo nft list table "$NFT_FAMILY" "$NFT_TABLE_NAME" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️ Création de la table nftables...${NC}"
        sudo nft add table "$NFT_FAMILY" "$NFT_TABLE_NAME"
        sudo nft add set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" "{ type ipv4_addr; }"
        sudo nft add chain "$NFT_FAMILY" "$NFT_TABLE_NAME" input "{ type filter hook input priority -300; policy accept; }"
        sudo nft add rule "$NFT_FAMILY" "$NFT_TABLE_NAME" input "ip saddr @$NFT_SET counter drop"
        log "Table nftables $NFT_FAMILY $NFT_TABLE_NAME créée"
        save_blacklist_persistent
    fi
}

nft_ban() {
    local ip="$1"
    local comment="$2"

    init_nftables
    if sudo nft add element "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" "{ $ip }" 2>/dev/null; then
        sudo conntrack -D -s "$ip" 2>/dev/null
        sudo ss -K dst "$ip" 2>/dev/null
        echo -e "${GREEN}✅ IP $ip bannie dans nftables${NC}"
        log "NFT_BAN: $ip | $comment"
        save_blacklist_persistent
        return 0
    else
        echo -e "${RED}❌ Erreur lors du bannissement dans nftables${NC}"
        return 1
    fi
}

nft_unban() {
    local ip="$1"

    if sudo nft delete element "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" "{ $ip }" 2>/dev/null; then
        echo -e "${GREEN}✅ IP $ip débannie de nftables${NC}"
        log "NFT_UNBAN: $ip"
        save_blacklist_persistent
        return 0
    else
        echo -e "${RED}❌ IP $ip non trouvée dans nftables${NC}"
        return 1
    fi
}

nft_list() {
    echo -e "${BLUE}📋 IPs bannies dans nftables:${NC}"
    echo ""

    local ips
    ips=$(sudo nft list set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

    if [ -z "$ips" ]; then
        echo -e "  ${YELLOW}⚠️ Aucune IP bannie${NC}"
    else
        while IFS= read -r ip; do
            [ -n "$ip" ] && echo -e "  • $ip"
        done <<< "$ips"

        local total
        total=$(echo "$ips" | sed '/^$/d' | wc -l)
        echo ""
        echo -e "${GREEN}✅ Total: $total IP(s)${NC}"
    fi
}

nft_flush() {
    echo -e "${YELLOW}⚠️  Vider toute la blacklist nftables ? (o/N)${NC}"
    read -r confirm
    if [[ $confirm =~ ^[OoYy]$ ]]; then
        sudo nft flush set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET"
        echo -e "${GREEN}✅ Blacklist nftables vidée${NC}"
        log "NFT_FLUSH: Toute la blacklist a été vidée"
        save_blacklist_persistent
    fi
}

# ============================================
# GESTION IPTABLES
# ============================================

iptables_ban() {
    local ip="$1"
    local comment="$2"

    if sudo iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo -e "${YELLOW}⚠️  IP $ip déjà bannie dans iptables${NC}"
        return 1
    fi

    if sudo iptables -I INPUT -s "$ip" -j DROP -m comment --comment "BLOCKLIST-MARKER" 2>/dev/null; then
        echo -e "${GREEN}✅ IP $ip bannie dans iptables${NC}"
        log "IPTABLES_BAN: $ip | $comment"
        save_iptables
        return 0
    else
        echo -e "${RED}❌ Erreur lors du bannissement dans iptables${NC}"
        return 1
    fi
}

iptables_unban() {
    local ip="$1"

    if sudo iptables -D INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo -e "${GREEN}✅ IP $ip débannie de iptables${NC}"
        log "IPTABLES_UNBAN: $ip"
        save_iptables
        return 0
    else
        echo -e "${RED}❌ IP $ip non trouvée dans iptables${NC}"
        return 1
    fi
}

iptables_list() {
    echo -e "${BLUE}📋 IPs bannies dans iptables:${NC}"
    echo ""

    local total=0
    while IFS= read -r line; do
        local ip pkts bytes
        ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        pkts=$(echo "$line" | awk '{print $1}')
        bytes=$(echo "$line" | awk '{print $2}')

        if [ -n "$ip" ]; then
            echo -e "  • $ip ${YELLOW}(pkts: $pkts, bytes: $bytes)${NC}"
            ((total++))
        fi
    done < <(sudo iptables -L INPUT -n -v | grep "DROP" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')

    echo ""
    echo -e "${GREEN}✅ Total: $total IP(s) bannie(s) dans iptables${NC}"
}

iptables_flush() {
    echo -e "${YELLOW}⚠️  Vider toutes les règles iptables marquées BLOCKLIST-MARKER ? (o/N)${NC}"
    read -r confirm
    if [[ $confirm =~ ^[OoYy]$ ]]; then
        sudo iptables -S INPUT | grep "BLOCKLIST-MARKER" | sed 's/^-A /-D /' | while IFS= read -r rule; do
            sudo iptables ${rule} 2>/dev/null
        done
        echo -e "${GREEN}✅ Blacklist iptables vidée${NC}"
        log "IPTABLES_FLUSH: Toute la blacklist iptables a été vidée"
        save_iptables
    fi
}

iptables_load_from_file() {
    local file="$1"
    local count=0
    local skipped=0

    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Fichier non trouvé: $file${NC}"
        return 1
    fi

    echo -e "${BLUE}📖 Lecture de $file...${NC}"

    while IFS= read -r line || [ -n "$line" ]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        local ip
        ip=$(echo "$line" | tr -d '[:space:]')

        if ! validate_ip "$ip"; then
            echo -e "${YELLOW}⚠️  Format invalide, ignoré: $line${NC}"
            ((skipped++))
            continue
        fi

        if iptables_ban "$ip" "load_from_file" >/dev/null 2>&1; then
            ((count++))
        fi
    done < "$file"

    echo -e "${GREEN}✅ $count IP(s) bannie(s) dans iptables depuis le fichier${NC}"
    [ "$skipped" -gt 0 ] && echo -e "${YELLOW}⚠️  $skipped ligne(s) ignorée(s)${NC}"
    save_iptables
}

# ============================================
# GESTION FICHIERS
# ============================================

load_from_file() {
    local file

    read -e -i "$DEFAULT_BLOCKLIST_FILE" -p "📁 Fichier à charger: " file
    file=${file:-$DEFAULT_BLOCKLIST_FILE}

    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Fichier introuvable: $file${NC}"
        pause
        return 1
    fi

    echo ""
    echo -e "${CYAN}📌 Destination du chargement :${NC}"
    echo -e "${GREEN}1)${NC} iptables"
    echo -e "${GREEN}2)${NC} nftables"
    echo -e "${GREEN}3)${NC} iptables + nftables"
    echo -e "${RED}0)${NC} Annuler"
    echo ""
    read -r -p "❓ Votre choix: " target

    local count=0
    local skipped=0

    case "$target" in
        1)
            iptables_load_from_file "$file"
            pause
            ;;
        2)
            echo -e "${BLUE}📖 Lecture de $file...${NC}"
            while IFS= read -r line || [ -n "$line" ]; do
                [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

                local ip
                ip=$(echo "$line" | tr -d '[:space:]')

                if ! validate_ip "$ip"; then
                    echo -e "${YELLOW}⚠️  Format invalide, ignoré: $line${NC}"
                    ((skipped++))
                    continue
                fi

                if nft_ban "$ip" "load_from_file" >/dev/null 2>&1; then
                    ((count++))
                fi
            done < "$file"

            echo -e "${GREEN}✅ $count IP(s) bannie(s) dans nftables depuis le fichier${NC}"
            [ "$skipped" -gt 0 ] && echo -e "${YELLOW}⚠️  $skipped ligne(s) ignorée(s)${NC}"
            pause
            ;;
        3)
            echo -e "${BLUE}📖 Lecture de $file...${NC}"
            while IFS= read -r line || [ -n "$line" ]; do
                [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

                local ip
                ip=$(echo "$line" | tr -d '[:space:]')

                if ! validate_ip "$ip"; then
                    echo -e "${YELLOW}⚠️  Format invalide, ignoré: $line${NC}"
                    ((skipped++))
                    continue
                fi

                nft_ban "$ip" "load_from_file" >/dev/null 2>&1
                iptables_ban "$ip" "load_from_file" >/dev/null 2>&1
                ((count++))
            done < "$file"

            echo -e "${GREEN}✅ $count IP(s) traitée(s) depuis le fichier${NC}"
            [ "$skipped" -gt 0 ] && echo -e "${YELLOW}⚠️  $skipped ligne(s) ignorée(s)${NC}"
            save_iptables
            save_blacklist_persistent
            pause
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${RED}❌ Choix invalide${NC}"
            pause
            return 1
            ;;
    esac
}

save_to_file() {
    local file

    read -e -i "$DEFAULT_BLOCKLIST_FILE" -p "📁 Fichier de sauvegarde: " file
    file=${file:-$DEFAULT_BLOCKLIST_FILE}

    echo ""
    echo -e "${CYAN}📌 Source à sauvegarder :${NC}"
    echo -e "${GREEN}1)${NC} iptables"
    echo -e "${GREEN}2)${NC} nftables"
    echo -e "${GREEN}3)${NC} iptables + nftables"
    echo -e "${RED}0)${NC} Annuler"
    echo ""
    read -r -p "❓ Votre choix: " source_choice

    sudo mkdir -p "$(dirname "$file")"

    case "$source_choice" in
        1)
            {
                echo "# Blocklist exportée le $(date '+%Y-%m-%d %H:%M:%S')"
                sudo iptables -L INPUT -n | grep -E 'DROP' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
            } | sudo tee "$file" > /dev/null
            ;;
        2)
            {
                echo "# Blocklist exportée le $(date '+%Y-%m-%d %H:%M:%S')"
                sudo nft list set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
            } | sudo tee "$file" > /dev/null
            ;;
        3)
            {
                echo "# Blocklist exportée le $(date '+%Y-%m-%d %H:%M:%S')"
                sudo nft list set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
                sudo iptables -L INPUT -n | grep -E 'DROP' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
            } | sort -u | sudo tee "$file" > /dev/null
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${RED}❌ Choix invalide${NC}"
            pause
            return 1
            ;;
    esac

    echo -e "${GREEN}✅ IPs sauvegardées dans $file${NC}"
    log "SAVE_TO_FILE: $file"
    pause
}

# ============================================
# GESTION FAIL2BAN
# ============================================

list_fail2ban_jails() {
    echo -e "${CYAN}📋 Jails fail2ban disponibles:${NC}"
    echo ""

    local i=1
    for jail in "${FAIL2BAN_JAILS[@]}"; do
        if sudo fail2ban-client status "$jail" &>/dev/null; then
            local banned
            banned=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned:" | awk '{print $4}')
            echo -e "  $i) $jail ${GREEN}($banned banniés)${NC}"
        else
            echo -e "  $i) $jail ${RED}(inactif)${NC}"
        fi
        ((i++))
    done
}

fail2ban_ban() {
    local jail="$1"
    local ip="$2"
    local comment="$3"

    if ! sudo fail2ban-client status "$jail" &>/dev/null; then
        echo -e "${RED}❌ Jail $jail inexistant ou inactif${NC}"
        return 1
    fi

    if sudo fail2ban-client set "$jail" banip "$ip" 2>/dev/null; then
        echo -e "${GREEN}✅ IP $ip bannie dans fail2ban ($jail)${NC}"
        log "FAIL2BAN_BAN: $jail | $ip | $comment"
        return 0
    else
        echo -e "${RED}❌ Erreur lors du bannissement dans fail2ban${NC}"
        return 1
    fi
}

fail2ban_unban() {
    local jail="$1"
    local ip="$2"

    if ! sudo fail2ban-client status "$jail" &>/dev/null; then
        echo -e "${RED}❌ Jail $jail inexistant ou inactif${NC}"
        return 1
    fi

    if sudo fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
        echo -e "${GREEN}✅ IP $ip débannie de fail2ban ($jail)${NC}"
        log "FAIL2BAN_UNBAN: $jail | $ip"
        return 0
    else
        echo -e "${RED}❌ Erreur lors du débannissement${NC}"
        return 1
    fi
}

# ============================================
# NOUVELLES FONCTIONS FAIL2BAN
# ============================================

fail2ban_flush_jail() {
    local jail="$1"

    if ! sudo fail2ban-client status "$jail" &>/dev/null; then
        echo -e "${RED}❌ Jail $jail inexistant ou inactif${NC}"
        return 1
    fi

    local before_count
    before_count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned:" | awk '{print $4}')
    
    if [ "${before_count:-0}" -eq 0 ]; then
        echo -e "${YELLOW}⚠️ Aucune IP bannie dans $jail${NC}"
        return 0
    fi

    echo -e "${YELLOW}⚠️  Vider le jail '$jail' (${before_count} IP(s)) ? (o/N)${NC}"
    read -r confirm
    if [[ ! $confirm =~ ^[OoYy]$ ]]; then
        echo -e "${YELLOW}⚠️ Annulé${NC}"
        return 0
    fi

    if sudo fail2ban-client reload --unban "$jail" 2>/dev/null; then
        echo -e "${GREEN}✅ Jail '$jail' vidé avec succès (reload --unban)${NC}"
        log "FAIL2BAN_FLUSH_JAIL: $jail (reload --unban) - ${before_count} IP(s) supprimée(s)"
        return 0
    fi

    echo -e "${YELLOW}⚠️ Fallback: débannissement individuel...${NC}"
    local ips
    ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:[[:space:]]*//')
    
    local count=0
    for ip in $ips; do
        if sudo fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
            echo -e "  • $ip débannie"
            ((count++))
        fi
    done

    echo -e "${GREEN}✅ $count IP(s) débannie(s) de $jail${NC}"
    log "FAIL2BAN_FLUSH_JAIL: $jail (fallback) - $count IP(s) supprimée(s)"
    return 0
}

fail2ban_transfer_to_blacklist() {
    local jail="$1"

    if ! sudo fail2ban-client status "$jail" &>/dev/null; then
        echo -e "${RED}❌ Jail $jail inexistant ou inactif${NC}"
        return 1
    fi

    local ips
    ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:[[:space:]]*//')
    
    if [ -z "$ips" ]; then
        echo -e "${YELLOW}⚠️ Aucune IP bannie dans $jail${NC}"
        return 0
    fi

    local total
    total=$(echo "$ips" | wc -w)
    
    echo -e "${CYAN}📌 Transfert de $total IP(s) de '$jail' vers la blacklist...${NC}"
    echo ""
    
    echo -e "${CYAN}📌 Destination :${NC}"
    echo -e "${GREEN}1)${NC} nftables uniquement"
    echo -e "${GREEN}2)${NC} iptables uniquement"
    echo -e "${GREEN}3)${NC} iptables + nftables"
    echo -e "${GREEN}4)${NC} Fichier ${DEFAULT_BLOCKLIST_FILE}"
    echo -e "${GREEN}5)${NC} Tous (nftables + iptables + fichier)"
    echo -e "${RED}0)${NC} Annuler"
    echo ""
    read -r -p "❓ Votre choix: " dest_choice

    local count=0
    local file_entries=""
    
    case "$dest_choice" in
        1|2|3|4|5)
            echo -e "${YELLOW}⚠️  Transférer $total IP(s) vers la destination choisie ? (o/N)${NC}"
            read -r confirm
            if [[ ! $confirm =~ ^[OoYy]$ ]]; then
                echo -e "${YELLOW}⚠️ Annulé${NC}"
                return 0
            fi

            for ip in $ips; do
                case "$dest_choice" in
                    1|3|5)
                        nft_ban "$ip" "transfer_from_fail2ban_$jail" >/dev/null 2>&1
                        ;;
                esac
                
                case "$dest_choice" in
                    2|3|5)
                        iptables_ban "$ip" "transfer_from_fail2ban_$jail" >/dev/null 2>&1
                        ;;
                esac
                
                case "$dest_choice" in
                    4|5)
                        file_entries="$file_entries$ip\n"
                        ;;
                esac
                
                ((count++))
                echo -ne "\r  📊 Progression: $count/$total"
            done
            
            echo ""

            if [[ "$dest_choice" == "4" || "$dest_choice" == "5" ]]; then
                if [ -n "$file_entries" ]; then
                    echo -e "$file_entries" | sort -u | sudo tee -a "$DEFAULT_BLOCKLIST_FILE" > /dev/null
                    echo -e "${GREEN}✅ IPs ajoutées à $DEFAULT_BLOCKLIST_FILE${NC}"
                fi
            fi

            echo -e "${GREEN}✅ Transfert terminé : $total IP(s) traitées${NC}"
            log "FAIL2BAN_TRANSFER: $jail -> $total IP(s) vers destination $dest_choice"
            ;;
        0)
            echo -e "${YELLOW}⚠️ Annulé${NC}"
            return 0
            ;;
        *)
            echo -e "${RED}❌ Choix invalide${NC}"
            return 1
            ;;
    esac
}

fail2ban_export_to_file() {
    local jail="$1"

    if ! sudo fail2ban-client status "$jail" &>/dev/null; then
        echo -e "${RED}❌ Jail $jail inexistant ou inactif${NC}"
        return 1
    fi

    local ips
    ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:[[:space:]]*//')
    
    if [ -z "$ips" ]; then
        echo -e "${YELLOW}⚠️ Aucune IP bannie dans $jail${NC}"
        return 0
    fi

    local total
    total=$(echo "$ips" | wc -w)
    
    echo -e "${CYAN}📌 Export de $total IP(s) du jail '$jail'${NC}"
    echo ""
    
    local output_file
    read -e -i "/tmp/fail2ban_${jail}_$(date +%Y%m%d).txt" -p "📁 Fichier de sortie: " output_file
    output_file=${output_file:-"/tmp/fail2ban_${jail}_$(date +%Y%m%d).txt"}

    {
        echo "# Export du jail fail2ban '$jail'"
        echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Total: $total IP(s)"
        echo "#"
        echo "$ips" | tr ' ' '\n' | sort -u
    } | sudo tee "$output_file" > /dev/null

    echo -e "${GREEN}✅ Export terminé : $output_file${NC}"
    echo -e "${CYAN}📋 Contenu :${NC}"
    echo ""
    sudo cat "$output_file"
    log "FAIL2BAN_EXPORT: $jail -> $total IP(s) exportées vers $output_file"
}

fail2ban_list() {
    local jail="$1"
    echo -e "${BLUE}📋 IPs bannies dans $jail:${NC}"
    echo ""

    local ips
    ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:[[:space:]]*//')

    if [ -z "$ips" ]; then
        echo -e "  ${YELLOW}⚠️ Aucune IP bannie${NC}"
    else
        echo "$ips" | tr ' ' '\n' | while IFS= read -r ip; do
            [ -n "$ip" ] && echo -e "  • $ip"
        done

        local total
        total=$(echo "$ips" | wc -w)
        echo ""
        echo -e "${GREEN}✅ Total: $total IP(s)${NC}"
    fi
}

fail2ban_show_all() {
    echo -e "${CYAN}📋 Récapitulatif fail2ban:${NC}"
    echo ""

    for jail in "${FAIL2BAN_JAILS[@]}"; do
        if sudo fail2ban-client status "$jail" &>/dev/null; then
            local banned
            banned=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned:" | awk '{print $4}')
            if [ "${banned:-0}" -gt 0 ]; then
                echo -e "  ${GREEN}✅ $jail:${NC} $banned IP(s)"
                local ips
                ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:[[:space:]]*//')
                echo "$ips" | tr ' ' '\n' | sed 's/^/      /'
            else
                echo -e "  ${YELLOW}⚠️ $jail:${NC} 0 IP"
            fi
        fi
    done
}

# ============================================
# MENU IPTABLES
# ============================================

iptables_menu() {
    while true; do
        clear_screen
        echo -e "${CYAN}🛠️         GESTION IPTABLES                🛠️${NC}"
        echo ""
        echo -e "${GREEN}1)${NC} Bannir une IP"
        echo -e "${GREEN}2)${NC} Débannir une IP"
        echo -e "${GREEN}3)${NC} Lister les IPs bannies"
        echo -e "${GREEN}4)${NC} Vider toute la blacklist iptables"
        echo -e "${GREEN}5)${NC} Charger la blocklist depuis /etc/blocklist.txt"
        echo -e "${GREEN}6)${NC} Synchroniser depuis nftables vers iptables"
        echo -e "${RED}0)${NC} Retour"
        echo ""
        read -r -p "❓ Votre choix: " choix

        case $choix in
            1)
                read -r -p "📌 IP à bannir: " ip
                validate_ip "$ip" && iptables_ban "$ip" "manual"
                pause
                ;;
            2)
                read -r -p "📌 IP à débannir: " ip
                iptables_unban "$ip"
                pause
                ;;
            3)
                iptables_list
                pause
                ;;
            4)
                iptables_flush
                pause
                ;;
            5)
                if [ -f "$DEFAULT_BLOCKLIST_FILE" ]; then
                    iptables_load_from_file "$DEFAULT_BLOCKLIST_FILE"
                else
                    echo -e "${RED}❌ $DEFAULT_BLOCKLIST_FILE n'existe pas${NC}"
                fi
                pause
                ;;
            6)
                echo -e "${CYAN}🔄 Synchronisation nftables -> iptables${NC}"
                echo ""

                local ips
                ips=$(sudo nft list set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

                if [ -z "$ips" ]; then
                    echo -e "${YELLOW}⚠️ Aucune IP dans nftables${NC}"
                else
                    while IFS= read -r ip; do
                        [ -n "$ip" ] || continue
                        echo -e "  • Ajout de $ip dans iptables..."
                        sudo iptables -I INPUT -s "$ip" -j DROP -m comment --comment "BLOCKLIST-MARKER" 2>/dev/null
                    done <<< "$ips"

                    echo -e "${GREEN}✅ Synchronisation terminée${NC}"
                    save_iptables
                fi
                pause
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}❌ Choix invalide${NC}"
                pause
                ;;
        esac
    done
}

# ============================================
# MENU PRINCIPAL
# ============================================

main_menu() {
    while true; do
        clear_screen
        echo -e "${GREEN}1)${NC} Gestion nftables (blacklist)"
        echo -e "${GREEN}2)${NC} Gestion iptables (recommandé pour Tailscale)"
        echo -e "${GREEN}3)${NC} Gestion fail2ban"
        echo -e "${GREEN}4)${NC} Gestion honeypots"
        echo -e "${GREEN}5)${NC} Gestion fichiers (charger/sauvegarder)"
        echo -e "${GREEN}6)${NC} Statistiques et monitoring"
        echo -e "${RED}0)${NC} Quitter"
        echo ""
        read -r -p "❓ Votre choix: " choix

        case $choix in
            1)
                while true; do
                    clear_screen
                    echo -e "${BLUE}🛠️         GESTION NFTABLES                🛠️${NC}"
                    echo ""
                    echo -e "${GREEN}1)${NC} Bannir une IP"
                    echo -e "${GREEN}2)${NC} Débannir une IP"
                    echo -e "${GREEN}3)${NC} Lister les IPs bannies"
                    echo -e "${GREEN}4)${NC} Vider toute la blacklist"
                    echo -e "${RED}0)${NC} Retour"
                    echo ""
                    read -r -p "❓ Choix: " sub
                    case $sub in
                        1) read -r -p "📌 IP: " ip; validate_ip "$ip" && nft_ban "$ip" "manual"; pause ;;
                        2) read -r -p "📌 IP: " ip; nft_unban "$ip"; pause ;;
                        3) nft_list; pause ;;
                        4) nft_flush; pause ;;
                        0) break ;;
                        *) echo -e "${RED}❌ Choix invalide${NC}"; pause ;;
                    esac
                done
                ;;
            2)
                iptables_menu
                ;;
            3)
                while true; do
                    clear_screen
                    echo -e "${MAGENTA}🛠️         GESTION FAIL2BAN                🛠️${NC}"
                    echo ""
                    list_fail2ban_jails
                    echo ""
                    echo -e "${GREEN}1)${NC} Bannir IP (choisir jail)"
                    echo -e "${GREEN}2)${NC} Débannir IP (choisir jail)"
                    echo -e "${GREEN}3)${NC} Lister IPs d'un jail"
                    echo -e "${GREEN}4)${NC} Voir tous les jails"
                    echo -e "${GREEN}5)${NC} Vider un jail entierement"
                    echo -e "${GREEN}6)${NC} Transférer IPs d'un jail vers la blocklist"
                    echo -e "${GREEN}7)${NC} Exporter IPs d'un jail vers un fichier"
                    echo -e "${RED}0)${NC} Retour"
                    echo ""
                    read -r -p "❓ Choix: " sub
                    case $sub in
                        1)
                            list_fail2ban_jails
                            read -r -p "📌 Numéro du jail: " jail_num
                            if [[ $jail_num =~ ^[0-9]+$ ]] && [ "$jail_num" -ge 1 ] && [ "$jail_num" -le "${#FAIL2BAN_JAILS[@]}" ]; then
                                jail="${FAIL2BAN_JAILS[$((jail_num-1))]}"
                                read -r -p "📌 IP: " ip
                                validate_ip "$ip" && fail2ban_ban "$jail" "$ip" "manual"
                            fi
                            pause
                            ;;
                        2)
                            list_fail2ban_jails
                            read -r -p "📌 Numéro du jail: " jail_num
                            if [[ $jail_num =~ ^[0-9]+$ ]] && [ "$jail_num" -ge 1 ] && [ "$jail_num" -le "${#FAIL2BAN_JAILS[@]}" ]; then
                                jail="${FAIL2BAN_JAILS[$((jail_num-1))]}"
                                read -r -p "📌 IP: " ip
                                fail2ban_unban "$jail" "$ip"
                            fi
                            pause
                            ;;
                        3)
                            list_fail2ban_jails
                            read -r -p "📌 Numéro du jail: " jail_num
                            if [[ $jail_num =~ ^[0-9]+$ ]] && [ "$jail_num" -ge 1 ] && [ "$jail_num" -le "${#FAIL2BAN_JAILS[@]}" ]; then
                                jail="${FAIL2BAN_JAILS[$((jail_num-1))]}"
                                fail2ban_list "$jail"
                            fi
                            pause
                            ;;
                        4)
                            fail2ban_show_all
                            pause
                            ;;
                        5)
                            list_fail2ban_jails
                            read -r -p "📌 Numéro du jail à vider: " jail_num
                            if [[ $jail_num =~ ^[0-9]+$ ]] && [ "$jail_num" -ge 1 ] && [ "$jail_num" -le "${#FAIL2BAN_JAILS[@]}" ]; then
                                jail="${FAIL2BAN_JAILS[$((jail_num-1))]}"
                                fail2ban_flush_jail "$jail"
                            else
                                echo -e "${RED}❌ Numéro invalide${NC}"
                            fi
                            pause
                            ;;
                        6)
                            list_fail2ban_jails
                            read -r -p "📌 Numéro du jail à transférer: " jail_num
                            if [[ $jail_num =~ ^[0-9]+$ ]] && [ "$jail_num" -ge 1 ] && [ "$jail_num" -le "${#FAIL2BAN_JAILS[@]}" ]; then
                                jail="${FAIL2BAN_JAILS[$((jail_num-1))]}"
                                fail2ban_transfer_to_blacklist "$jail"
                            else
                                echo -e "${RED}❌ Numéro invalide${NC}"
                            fi
                            pause
                            ;;
                        7)
                            list_fail2ban_jails
                            read -r -p "📌 Numéro du jail à exporter: " jail_num
                            if [[ $jail_num =~ ^[0-9]+$ ]] && [ "$jail_num" -ge 1 ] && [ "$jail_num" -le "${#FAIL2BAN_JAILS[@]}" ]; then
                                jail="${FAIL2BAN_JAILS[$((jail_num-1))]}"
                                fail2ban_export_to_file "$jail"
                            else
                                echo -e "${RED}❌ Numéro invalide${NC}"
                            fi
                            pause
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo -e "${RED}❌ Choix invalide${NC}"
                            pause
                            ;;
                    esac
                done
                ;;
            4)
                echo -e "${YELLOW}⚠️ Gestion honeypots : utilisez fail2ban (option 3)${NC}"
                pause
                ;;
            5)
                while true; do
                    clear_screen
                    echo -e "${CYAN}📁         GESTION FICHIERS                📁${NC}"
                    echo ""
                    echo -e "${GREEN}1)${NC} Charger des IPs depuis un fichier"
                    echo -e "${GREEN}2)${NC} Sauvegarder les IPs dans un fichier"
                    echo -e "${GREEN}3)${NC} Éditer /etc/blocklist.txt (nano)"
                    echo -e "${RED}0)${NC} Retour"
                    echo ""
                    read -r -p "❓ Votre choix: " sub
                    case $sub in
                        1) load_from_file ;;
                        2) save_to_file ;;
                        3) sudo nano "$DEFAULT_BLOCKLIST_FILE"; echo -e "${GREEN}✅ Fichier édité${NC}"; pause ;;
                        0) break ;;
                        *) echo -e "${RED}❌ Choix invalide${NC}"; pause ;;
                    esac
                done
                ;;
            6)
                clear_screen
                echo -e "${CYAN}📊         STATISTIQUES                    📊${NC}"
                echo ""

                local nft_count
                local iptables_count

                nft_count=$(sudo nft list set "$NFT_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET" 2>/dev/null | grep -cE '([0-9]{1,3}\.){3}[0-9]{1,3}' || echo "0")
                iptables_count=$(sudo iptables -L INPUT -n -v | grep "BLOCKLIST-MARKER" | grep -cE '([0-9]{1,3}\.){3}[0-9]{1,3}' || echo "0")

                echo -e "${BLUE}🛡️ nftables:${NC}  $nft_count IP(s) bannie(s)"
                echo -e "${BLUE}🛡️ iptables:${NC}  $iptables_count IP(s) bannie(s)"
                echo ""
                fail2ban_show_all
                echo ""
                echo -e "${YELLOW}📋 Log file: $LOG_FILE${NC}"
                pause
                ;;
            0)
                echo -e "${GREEN}✅ Au revoir !${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Choix invalide${NC}"
                pause
                ;;
        esac
    done
}

# ============================================
# LANCEMENT
# ============================================

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Ce script doit être exécuté avec sudo${NC}"
    exit 1
fi

touch "$LOG_FILE" 2>/dev/null
main_menu
