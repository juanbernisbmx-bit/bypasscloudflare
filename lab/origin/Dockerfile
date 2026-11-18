# El servidor de ORIGEN a descubrir: una sola caja con web (80/443), FTP (21)
# y SSH en 2222 -- igual que el hallazgo real (un VPS con varios servicios).
FROM alpine:3.20
RUN apk add --no-cache nginx openssh vsftpd openssl bash
# Usuario de laboratorio (credenciales triviales: es un lab, no produccion).
RUN adduser -D -h /home/labuser labuser && echo "labuser:labpass123" | chpasswd
COPY index.html /www/index.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 21 80 443 2222
ENTRYPOINT ["/entrypoint.sh"]
