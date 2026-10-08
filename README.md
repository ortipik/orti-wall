<div align="center">
  <img src="https://raw.githubusercontent.com/ortipik/ortipik/refs/heads/main/docs/assets/orti-wall.png" alt="Orti-wall" width="384">
</div>

# 🔥 orti-wall — nftables, fail2ban & iptables

[![Bash](https://img.shields.io/badge/Bash-5.0%2B-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Debian%20%7C%20Arch-FCC624?logo=linux&logoColor=black)](https://www.kernel.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](#-licence)
[![Version](https://img.shields.io/badge/version-2.0-00d4ff.svg)](#)

> **Gestion centralisée de votre infrastructure de sécurité** : `nftables`, `fail2ban` et `iptables` réunis dans un seul script Bash interactif.

---

## 📖 Sommaire

- [Présentation](#-présentation)
- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [Résilience & robustesse](#-résilience--robustesse)
- [Arborescence du menu](#-arborescence-du-menu)
- [Détails techniques](#-détails-techniques)
- [Sécurité](#-sécurité)
- [FAQ](#-faq)
- [Licence](#-licence)

---

## 🎯 Présentation

**Firewall Manager** est un script Bash conçu pour unifier la gestion de trois composants majeurs de la sécurité réseau sous Linux :

| Composant | Rôle |
|-----------|------|
| 🛡️ **nftables** | Pare-feu moderne (successeur d'iptables) |
| 🐝 **fail2ban** | Détection d'intrusion et bannissement automatique |
| 🔒 **iptables** | Pare-feu traditionnel (compatible Tailscale, Docker…) |

Il permet de bannir des IPs, gérer des blacklists persistantes, transférer les IPs bannies par fail2ban vers nftables ou iptables, et maintenir une **cohérence globale** entre tous ces systèmes.

Élaboré par **Ortipik** pour [OMEGA-server](https://kraynux.snake-mackarel.ts.net).

---

## ✨ Fonctionnalités

### 🛡️ nftables
- Bannir / débannir une IP
- Lister les IPs de la blacklist
- Vider entièrement la blacklist
- Sauvegarde persistante dans `/etc/nftables-blacklist.conf`

### 🔒 iptables
- Bannir / débannir une IP
- Lister les IPs (avec compteurs pkts/bytes)
- Vider toutes les règles marquées `BLOCKLIST-MARKER`
- **Synchroniser depuis nftables** vers iptables
- Chargement depuis un fichier texte

### 🐝 fail2ban
- Bannir / débannir une IP sur un jail spécifique
- Lister les IPs bannies par jail
- **Vider un jail entier** (`reload --unban` + fallback individuel)
- **Transférer les IPs d'un jail** vers nftables / iptables / fichier / tous
- **Exporter un jail** vers un fichier texte
- Récapitulatif de tous les jails avec compteurs

### 📁 Gestion fichiers
- Charger une blocklist depuis un fichier (vers nftables, iptables ou les deux)
- Sauvegarder les IPs bannies vers un fichier
- Édition rapide via `nano`

### 📊 Statistiques
- Nombre d'IPs bannies dans nftables et iptables
- Récapitulatif de tous les jails fail2ban
- Emplacement du fichier de logs

---

## 📋 Prérequis

- **Bash** 5.0 ou supérieur
- **`sudo`** (le script doit être exécuté en root)
- **Optionnels** (le script fonctionne même s'ils sont absents) :
  - `nftables` (`nft`)
  - `fail2ban` (`fail2ban-client`)
  - `iptables`
  - `conntrack` (pour tuer les connexions actives)
  - `ss` (issu de `iproute2`)

### Installation des dépendances

**Debian / Ubuntu :**
```bash
sudo apt update
sudo apt install nftables fail2ban iptables conntrack iproute2
```

**Arch Linux :**
```bash
sudo pacman -S nftables fail2ban iptables conntrack-tools iproute2
```

**Fedora / RHEL :**
```bash
sudo dnf install nftables fail2ban iptables conntrack-tools iproute
```

---

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/Ortipik/orti-wall.git
cd orti-wall

# Rendre le script exécutable
chmod +x orti-wall.sh

# Lancer
sudo ./orti-wall.sh
```

**Installation globale (optionnelle) :**
```bash
sudo cp orti-wall.sh /usr/local/bin/orti-wall
sudo chmod +x /usr/local/bin/orti-wall
sudo orti-wall
```

---

## ⚙️ Configuration

Toute la configuration se trouve dans la section **`PARTIE A CONFIGURER`** en tête du script :

```bash
#============ PARTIE A CONFIGURER ======================================
NFT_FAMILY="inet"                      # Famille nftables
NFT_TABLE_NAME="myblacklist"           # Nom de la table nftables
NFT_SET="blacklist"                    # Nom du set contenant les IPs
LOG_FILE="/var/log/firewall-manager.log"
IPTABLES_SAVE="/etc/iptables/iptables.rules"
DEFAULT_BLOCKLIST_FILE="/etc/blocklist.txt"
FAIL2BAN_JAILS=("honeypot" "aggressive" "agents" "honeypot" "ipv6" \
                "critical-ipv6" "scanner" "404" "sshd" "ftp" \
                "recidive" "web" "manual-blacklist")
#========== FIN DE LA PARTIE A CONFIGURER ==============================
```

### Variables

| Variable | Description | Valeur par défaut |
|----------|-------------|-------------------|
| `NFT_FAMILY` | Famille nftables (`inet`, `ip`, `ip6`, `arp`, `bridge`) | `inet` |
| `NFT_TABLE_NAME` | Nom de la table nftables | `myblacklist` |
| `NFT_SET` | Nom du set contenant les IPs | `blacklist` |
| `LOG_FILE` | Fichier de logs | `/var/log/firewall-manager.log` |
| `IPTABLES_SAVE` | Sauvegarde des règles iptables | `/etc/iptables/iptables.rules` |
| `DEFAULT_BLOCKLIST_FILE` | Fichier blocklist par défaut | `/etc/blocklist.txt` |
| `FAIL2BAN_JAILS` | Tableau des jails fail2ban à gérer | *(exemples)* |

> 💡 **Conseil** : adaptez `FAIL2BAN_JAILS` à vos propres jails (`fail2ban-client status` pour les lister).

---

## 🎮 Utilisation

```bash
sudo ./orti-wall.sh
```

### Menu principal

```
▶️ ============================================================= ▶️
     FIREWALL MANAGER - v2.0 nftables-fail2ban-iptables       
▶️ ============================================================= ▶️

1) Gestion nftables (blacklist)
2) Gestion iptables (recommandé pour Tailscale)
3) Gestion fail2ban
4) Gestion honeypots
5) Gestion fichiers (charger/sauvegarder)
6) Statistiques et monitoring
0) Quitter

❓ Votre choix:
```

Naviguez avec les chiffres puis validez avec <kbd>Entrée</kbd>.

### Exemples d'utilisation

**Bannir une IP manuellement dans nftables :**
```
1 → 1 → 192.168.1.100
```

**Transférer toutes les IPs du jail `sshd` vers nftables + iptables + fichier :**
```
3 → 6 → [numéro du jail] → 5 → o
```

**Exporter un jail vers un fichier :**
```
3 → 7 → [numéro du jail] → /tmp/export.txt
```

**Charger une blocklist depuis un fichier :**
```
5 → 1 → /etc/blocklist.txt → 3 (iptables + nftables)
```

---

## 🛡️ Résilience & robustesse

Le script est conçu pour être **non bloquant** :

- ✅ **Absence de `set -e`** — Bash continue même en cas d'erreur
- ✅ **Vérifications conditionnelles** — chaque action est encapsulée dans des `if` testant le code retour
- ✅ **Masquage des erreurs système** — `2>/dev/null` et `&>/dev/null` évitent les messages bruts
- ✅ **Gestion sécurisée de fail2ban** — vérification de l'existence des jails avant action
- ✅ **Initialisation défensive** — `init_nftables()` échoue proprement si nftables est absent

Même si un outil est complètement désinstallé, le script affiche un message clair (✅/❌/⚠️) et retourne au menu **sans s'interrompre**.

---

## 🗂️ Arborescence du menu

```
📋 Menu principal
├── 🛡️ 1. Gestion nftables
│   ├── Bannir une IP
│   ├── Débannir une IP
│   ├── Lister les IPs
│   └── Vider la blacklist
├── 🔒 2. Gestion iptables
│   ├── Bannir / Débannir
│   ├── Lister / Vider
│   ├── Charger depuis /etc/blocklist.txt
│   └── Synchroniser depuis nftables
├── 🐝 3. Gestion fail2ban
│   ├── Bannir / Débannir une IP
│   ├── Lister les IPs d'un jail
│   ├── Voir tous les jails
│   ├── Vider un jail entier
│   ├── Transférer IPs → blocklist
│   └── Exporter IPs → fichier
├── 🍯 4. Gestion honeypots (via fail2ban)
├── 📁 5. Gestion fichiers
│   ├── Charger
│   ├── Sauvegarder
│   └── Éditer /etc/blocklist.txt
└── 📊 6. Statistiques et monitoring
```

---

## 🔧 Détails techniques

### Commandes système utilisées

| Commande | Usage |
|----------|-------|
| `nft` | Gestion des tables, sets et règles nftables |
| `iptables` | Règles de filtrage IPv4 avec marqueur `BLOCKLIST-MARKER` |
| `fail2ban-client` | API de bannissement/débannissement fail2ban |
| `conntrack -D` | Suppression des connexions actives d'une IP bannie |
| `ss -K dst` | Fermeture des sockets actifs vers une IP bannie |

### Fichiers manipulés

| Fichier | Rôle |
|---------|------|
| `/var/log/firewall-manager.log` | Journal des actions |
| `/etc/blocklist.txt` | Blocklist persistante |
| `/etc/nftables-blacklist.conf` | Sauvegarde nftables |
| `/etc/iptables/iptables.rules` | Sauvegarde iptables |

### Validation des IPs

Chaque IP est validée par la fonction `validate_ip()` (format + plage 0-255) avant toute action.

---

## 🔐 Sécurité

> ⚠️ **Attention** : ce script modifie les règles de pare-feu et les blacklists. **Soyez prudent lorsque vous bannissez des IPs** — vérifiez toujours que vous ne vous bannissez pas vous-même (notamment via SSH).

**Bonnes pratiques :**

1. Toujours tester sur un environnement de staging avant la production
2. Sauvegarder vos règles iptables/nftables avant utilisation :
   ```bash
   sudo iptables-save > /root/iptables.backup
   sudo nft list ruleset > /root/nftables.backup
   ```
3. Ajouter votre IP d'administration en **whitelist** dans votre configuration fail2ban
4. Ne jamais exécuter le script via une session SSH que vous risquez de couper

---

## ❓ FAQ

<details>
<summary><strong>Le script plante si nftables n'est pas installé ?</strong></summary>

Non. Le script est résilient : chaque appel est encapsulé dans des vérifications conditionnelles et les erreurs sont masquées. Un message clair est affiché et vous revenez au menu.

</details>

<details>
<summary><strong>Comment ajouter un jail fail2ban personnalisé ?</strong></summary>

Ajoutez simplement le nom du jail dans le tableau `FAIL2BAN_JAILS` en tête du script :
```bash
FAIL2BAN_JAILS=("sshd" "web" "mon-jail-custom")
```

</details>

<details>
<summary><strong>Comment fonctionne la synchronisation nftables → iptables ?</strong></summary>

Le script lit toutes les IPs du set nftables et les réinjecte dans iptables avec le marqueur `BLOCKLIST-MARKER`, ce qui permet de les supprimer facilement via l'option "Vider la blacklist iptables".

</details>

<details>
<summary><strong>Pourquoi deux pare-feu (nftables + iptables) ?</strong></summary>

Certains environnements (Tailscale, Docker, Kubernetes) manipulent directement iptables. nftables est le pare-feu natif moderne. Ce script permet de maintenir une cohérence entre les deux pour éviter qu'une IP bannie côté nftables ne repasse côté iptables.

</details>

<details>
<summary><strong>Où sont stockés les logs ?</strong></summary>

Par défaut dans `/var/log/firewall-manager.log` (chemin configurable via `LOG_FILE`).

</details>

---

## 🤝 Contribuer

Les contributions sont les bienvenues !

1. Forkez le projet
2. Créez votre branche : `git checkout -b feature/ma-fonctionnalite`
3. Committez vos changements : `git commit -m 'Ajout de ma fonctionnalité'`
4. Pushez : `git push origin feature/ma-fonctionnalite`
5. Ouvrez une Pull Request

---

## 📜 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus d'informations.

---

## 👤 Auteur

**Ortipik** — pour [OMEGA-server](https://kraynux.snake-mackarel.ts.net)

- 🌐 Page: [orti-wall](https://kraynux.snake-mackarel.ts.net/public/scripts/Firewall-manager-nftables-iptables-fail2ban.html)
- 🐙 GitHub : [@Ortipik](https://github.com/Ortipik)
---

<div align="center">

**⭐ Si ce projet vous est utile, n'oubliez pas de lui mettre une étoile ! ⭐**

`© 2026 – Tutoriels Omega – Scripts & outils pour développeurs`

</div>
