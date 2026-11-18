#!/bin/sh
set -e

# --- Certificado autofirmado para el lab (ejercita el manejo de TLS invalido) ---
mkdir -p /etc/nginx/certs
if [ ! -f /etc/nginx/certs/origin.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout /etc/nginx/certs/origin.key -out /etc/nginx/certs/origin.crt \
        -subj "/CN=bataedu.lab" \
        -addext "subjectAltName=DNS:bataedu.lab,DNS:admin.bataedu.lab,DNS:api.bataedu.lab,DNS:auth.bataedu.lab" 2>/dev/null
fi

# --- nginx: sirve la app en 80 y 443, SIN cabecera cf-ray (es el origen real) ---
mkdir -p /run/nginx
cat > /etc/nginx/http.d/default.conf <<'EOF'
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_certificate     /etc/nginx/certs/origin.crt;
    ssl_certificate_key /etc/nginx/certs/origin.key;
    server_name _;
    root /www;
    index index.html;
}
EOF

# --- SSH en 2222 ---
ssh-keygen -A
mkdir -p /run/sshd /var/empty
sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config
/usr/sbin/sshd

# --- FTP (vsftpd) con anonimo de solo lectura: para practicar nmap/ftp-anon ---
mkdir -p /var/ftp/pub
echo "lab ftp - solo practica" > /var/ftp/pub/readme.txt
chown -R ftp:ftp /var/ftp
cat > /etc/vsftpd/vsftpd.conf <<'EOF'
listen=YES
anonymous_enable=YES
anon_root=/var/ftp
local_enable=NO
write_enable=NO
seccomp_sandbox=NO
secure_chroot_dir=/var/ftp
EOF
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &

# --- nginx en primer plano (mantiene vivo el contenedor) ---
exec nginx -g 'daemon off;'
