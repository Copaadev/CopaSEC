# CopaSec 2.0


**Security Recon Framework** para terminal, feito em Python puro (sem dependências externas).

> ⚠️ **Uso autorizado apenas.** Use somente em máquinas e redes que você possui ou para as quais tem permissão explícita: laboratório próprio, CTFs permitidos e administração de sistemas. O autor não se responsabiliza pelo uso indevido.

## Recursos

| #  | Ferramenta         | O que faz                                        | Depende de   |
|----|--------------------|--------------------------------------------------|--------------|
| 1  | Network Scanner    | Descoberta de hosts (IP, domínio ou rede CIDR)   | `nmap`       |
| 2  | Port Scanner       | Portas abertas (top 100/1000, lista ou faixa)    | `nmap`       |
| 3  | Service Detection  | Serviços e versões nas portas abertas            | `nmap`       |
| 4  | Banner Grabber     | Lê o banner de um serviço TCP                    | -            |
| 5  | DNS Recon          | A, AAAA, MX, NS, TXT, CNAME, SOA e DNS reverso   | `dig`*       |
| 6  | Subdomain Finder   | Subdomínios por wordlist, detecta wildcard DNS   | -            |
| 7  | HTTP Analysis      | Status, headers, servidor, HTTPS e título        | -            |
| 8  | Security Headers   | Auditoria de cabeçalhos de segurança + pontuação | -            |
| 9  | SSL/TLS Analysis   | Certificado, emissor, validade, protocolo, cipher| -            |
| 10 | WHOIS Lookup       | Dados de registro de domínio/IP                  | `whois`      |
| 11 | Traceroute         | Caminho de rede até o alvo                       | `traceroute` |

\* Sem `dig`, o DNS Recon mostra apenas A/AAAA.

Em desenvolvimento: **Full Recon**, **Relatórios** (TXT/JSON/HTML), **Logs** e **Settings** pelo menu.

## Requisitos

- Linux (desenvolvido e testado no Arch Linux)
- Python 3.9+
- Ferramentas opcionais, dependendo da opção usada:

```bash
sudo pacman -S nmap bind whois traceroute
```

O CopaSec **nunca** executa `sudo` nem instala nada sozinho. Quando falta uma ferramenta, ele mostra o comando de instalação.

## Instalação

```bash
git clone https://github.com/Copaadev/copasec.git copasec
cd copasec
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 copasec.py
```

### Abrir com um único comando

```bash
mkdir -p ~/.local/bin
cat > ~/.local/bin/copasec << 'LAUNCHER'
#!/bin/sh
exec python3 "$HOME/copasec/copasec.py" "$@"
LAUNCHER
chmod +x ~/.local/bin/copasec
```

Garanta que `~/.local/bin` está no `PATH` e depois rode apenas:

```bash
copasec
```

## Uso

Execute `copasec`, escolha uma opção pelo número e informe o alvo. Exemplos de alvo:

- IP: `192.168.0.10`
- Domínio: `exemplo.com`
- Rede (só Network Scanner): `192.168.0.0/24`

Antes de cada alvo novo, o programa pergunta se você tem autorização para testá-lo.

Portas (Port Scanner e Service Detection): `ENTER` = top 100, `top1000`, `all`, lista (`22,80,443`) ou faixa (`1-1024`).

## Configuração

Arquivo `config.json`, na raiz do projeto:

```json
{
  "theme": "matrix",
  "timeout": 30,
  "report_dir": "reports",
  "log_dir": "logs",
  "verbosity": "normal"
}
```

| Chave       | Valores                              |
|-------------|--------------------------------------|
| `theme`     | `dark`, `matrix`, `red`, `purple`    |
| `timeout`   | 1 a 600 (segundos)                   |
| `verbosity` | `quiet`, `normal`, `verbose`         |

Valores inválidos ou arquivo ausente/corrompido voltam aos padrões, sem quebrar o programa.

## Estrutura

```text
copasec/
├── copasec.py        # ponto de entrada e boot
├── actions.py        # liga o menu aos módulos
├── menu.py           # menu interativo
├── banner.py         # banner ASCII
├── animation.py      # animação de boot e spinner
├── colors.py         # cores, temas e mensagens [+] [✓] [!] [-]
├── output.py         # seções, tabelas e erros
├── prompts.py        # entrada validada e confirmação de autorização
├── targets.py        # validação de alvos e portas
├── runner.py         # execução segura de comandos externos
├── settings.py       # carregamento do config.json
├── nmap_scan.py      # módulos 1, 2 e 3
├── banner_grab.py    # módulo 4
├── dns_recon.py      # módulos 5 e 6
├── http_analysis.py  # módulos 7 e 8
├── ssl_analysis.py   # módulo 9
├── intel.py          # módulos 10 e 11
├── config.json
├── requirements.txt
├── reports/
└── logs/
```

Cada módulo expõe uma função que devolve um resultado estruturado (`dict`) e uma função `render_*` que o exibe. Isso facilita encadear módulos (Full Recon) e gerar relatórios.

## Segurança do próprio programa

- Comandos externos rodam com `subprocess.run()` e **lista de argumentos**, sem `shell=True` e sem `os.system`.
- Todo alvo e porta é validado antes de chegar a qualquer comando; entradas começando com `-` ou com caracteres especiais são rejeitadas.
- Sem exploração, brute force de credenciais, persistência ou qualquer ação destrutiva: apenas reconhecimento e auditoria.
- `Ctrl+C`, alvo inválido, ferramenta ausente, timeout e erros de rede mostram mensagens amigáveis, sem traceback.

## Adicionar um módulo

1. Crie `meu_modulo.py` com uma função que retorna `new_result(...)` (de `runner.py`) e uma função `render_*`.
2. Registre o handler em `actions.py` e a linha em `SECTIONS` no `menu.py`.

## Roadmap

- [x] Menu, temas, banner e animações
- [x] Nmap, DNS, HTTP, SSL/TLS, WHOIS, traceroute, banner grabber
- [ ] Full Recon (execução encadeada com progresso)
- [ ] Relatórios TXT, JSON e HTML organizados por alvo e data
- [ ] Logs (`logs/copasec.log`)
- [ ] Tela de Settings dentro do programa

## Aviso legal

Esta ferramenta é fornecida para fins educacionais e de administração de sistemas. Escanear sistemas sem autorização pode ser crime. Você é o único responsável pelo uso que fizer dela.
