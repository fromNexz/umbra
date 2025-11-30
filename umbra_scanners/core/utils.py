"""
Umbra Scanners - Core Utilities
Funções puras para validação, sanitização e helpers gerais.
"""

import re
import socket
import ipaddress
import uuid
from typing import Union, Optional, List, Any
from datetime import datetime, timezone
import hashlib
import validators


# ============================================
# Validação de Entrada
# ============================================

def is_valid_ip(ip: str) -> bool:
    """
    Valida se uma string é um endereço IP válido (v4 ou v6).
    
    Args:
        ip: String contendo o IP
        
    Returns:
        bool: True se válido, False caso contrário
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Valida se uma string é um domínio válido.
    
    Args:
        domain: String contendo o domínio
        
    Returns:
        bool: True se válido, False caso contrário
    """
    return validators.domain(domain) is True


def is_valid_url(url: str) -> bool:
    """
    Valida se uma string é uma URL válida.
    
    Args:
        url: String contendo a URL
        
    Returns:
        bool: True se válido, False caso contrário
    """
    return validators.url(url) is True


def is_valid_port(port: Union[int, str]) -> bool:
    """
    Valida se um valor é uma porta válida (1-65535).
    
    Args:
        port: Número da porta (int ou string)
        
    Returns:
        bool: True se válido, False caso contrário
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


# ============================================
# Sanitização de Entrada
# ============================================

def sanitize_input(user_input: str) -> str:
    """
    Remove caracteres perigosos de input do usuário.
    Previne command injection e path traversal.
    
    Args:
        user_input: String de entrada do usuário
        
    Returns:
        str: String sanitizada
    """
    # Remove caracteres perigosos para shell
    dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\r']
    sanitized = user_input
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    # Remove path traversal
    sanitized = sanitized.replace('..', '')
    sanitized = sanitized.replace('//', '/')
    
    return sanitized.strip()


def normalize_target(target: str) -> dict:
    """
    Normaliza um alvo (IP, domínio ou URL) e retorna informações estruturadas.
    
    Args:
        target: String contendo IP, domínio ou URL
        
    Returns:
        dict: {
            'original': str,
            'type': 'ip' | 'domain' | 'url',
            'normalized': str,
            'ip': str | None,
            'domain': str | None,
            'valid': bool
        }
    """
    target = sanitize_input(target)
    
    result = {
        'original': target,
        'type': None,
        'normalized': target,
        'ip': None,
        'domain': None,
        'valid': False
    }
    
    # Verifica se é IP
    if is_valid_ip(target):
        result['type'] = 'ip'
        result['ip'] = target
        result['normalized'] = target
        result['valid'] = True
        return result
    
    # Verifica se é localhost (caso especial)
    if target.lower() in ['localhost', 'localhost.localdomain']:
        result['type'] = 'domain'
        result['domain'] = 'localhost'
        result['normalized'] = 'localhost'
        result['valid'] = True
        return result
    
    # Verifica se é URL
    if is_valid_url(target):
        result['type'] = 'url'
        result['normalized'] = target
        result['valid'] = True
        
        # Extrai domínio da URL
        match = re.search(r'://([^/:]+)', target)
        if match:
            result['domain'] = match.group(1)
        
        return result
    
    # Verifica se é domínio
    if is_valid_domain(target):
        result['type'] = 'domain'
        result['domain'] = target
        result['normalized'] = target
        result['valid'] = True
        return result
    
    return result


# ============================================
# Resolução de DNS
# ============================================

def resolve_hostname(hostname: str, timeout: int = 3) -> Optional[str]:
    """
    Resolve um hostname para endereço IP.
    
    Args:
        hostname: Nome do host a resolver
        timeout: Timeout em segundos
        
    Returns:
        str: Endereço IP ou None se falhar
    """
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except (socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)


def reverse_dns(ip: str, timeout: int = 3) -> Optional[str]:
    """
    Faz reverse DNS lookup de um IP.
    
    Args:
        ip: Endereço IP
        timeout: Timeout em segundos
        
    Returns:
        str: Hostname ou None se falhar
    """
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)


# ============================================
# Geração de IDs e Hashes
# ============================================

def generate_trace_id() -> str:
    """
    Gera um trace_id único para correlação de logs.
    
    Returns:
        str: UUID v4 como string
    """
    return str(uuid.uuid4())


def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """
    Gera hash de uma string.
    
    Args:
        text: Texto a ser hasheado
        algorithm: Algoritmo (md5, sha1, sha256)
        
    Returns:
        str: Hash hexadecimal
    """
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(text.encode('utf-8'))
    return hash_obj.hexdigest()


# ============================================
# Manipulação de Timestamps
# ============================================

def get_timestamp_utc() -> str:
    """
    Retorna timestamp atual em formato ISO 8601 UTC.
    
    Returns:
        str: Timestamp no formato '2025-11-29T15:00:00Z'
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Converte string ISO 8601 para objeto datetime.
    
    Args:
        timestamp_str: String no formato ISO 8601
        
    Returns:
        datetime: Objeto datetime ou None se inválido
    """
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


# ============================================
# Normalização de Scores
# ============================================

def clamp(value: float, min_value: float = -0.3, max_value: float = 2.0) -> float:
    """
    Limita um valor entre min e max (para scoring do Umbra).
    
    Args:
        value: Valor a ser limitado
        min_value: Valor mínimo permitido
        max_value: Valor máximo permitido
        
    Returns:
        float: Valor limitado
    """
    return max(min_value, min(value, max_value))


def normalize_score(raw_score: float) -> float:
    """
    Normaliza score bruto para escala do Umbra (-0.3 a 2.0).
    
    Args:
        raw_score: Score bruto (pode ser qualquer valor)
        
    Returns:
        float: Score normalizado entre -0.3 e 2.0
    """
    return clamp(raw_score, -0.3, 2.0)


# ============================================
# Manipulação de Listas de Portas
# ============================================

def parse_port_range(port_range: str) -> List[int]:
    """
    Converte string de portas/ranges em lista de portas.
    
    Exemplos:
        "80" -> [80]
        "80,443" -> [80, 443]
        "20-25" -> [20, 21, 22, 23, 24, 25]
        "80,443,8000-8003" -> [80, 443, 8000, 8001, 8002, 8003]
    
    Args:
        port_range: String com portas separadas por vírgula e/ou ranges
        
    Returns:
        List[int]: Lista de portas válidas
    """
    ports = set()
    
    for part in port_range.split(','):
        part = part.strip()
        
        # Range de portas (ex: 20-25)
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if is_valid_port(start) and is_valid_port(end) and start <= end:
                    ports.update(range(start, end + 1))
            except ValueError:
                continue
        
        # Porta única
        else:
            try:
                port = int(part)
                if is_valid_port(port):
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(list(ports))


def get_common_ports(category: str = 'all') -> List[int]:
    """
    Retorna lista de portas comuns por categoria.
    
    Args:
        category: 'all', 'web', 'ftp', 'ssh', 'db', 'mail', 'top100', 'top1000'
        
    Returns:
        List[int]: Lista de portas
    """
    categories = {
        'web': [80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
        'ftp': [20, 21],
        'ssh': [22],
        'db': [3306, 5432, 27017, 6379, 1433, 5984],
        'mail': [25, 110, 143, 587, 993, 995],
        'top100': list(range(1, 101)),
        'top1000': list(range(1, 1001))
    }
    
    if category in categories:
        return categories[category]
    
    # 'all' - retorna top 1000 + portas específicas
    all_ports = set(categories['top1000'])
    for ports in categories.values():
        if isinstance(ports, list):
            all_ports.update(ports)
    
    return sorted(list(all_ports))


# ============================================
# Helpers de String
# ============================================

def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Trunca string se exceder tamanho máximo.
    
    Args:
        text: Texto a truncar
        max_length: Tamanho máximo
        suffix: Sufixo a adicionar se truncar
        
    Returns:
        str: Texto truncado
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def extract_banner(raw_data: bytes, max_length: int = 1024) -> str:
    """
    Extrai banner de dados binários recebidos de socket.
    
    Args:
        raw_data: Dados brutos recebidos
        max_length: Tamanho máximo do banner
        
    Returns:
        str: Banner como string (decoded)
    """
    try:
        # Tenta decodificar como UTF-8
        banner = raw_data[:max_length].decode('utf-8', errors='ignore')
        
        # Remove caracteres de controle
        banner = ''.join(char for char in banner if char.isprintable() or char in '\n\r\t')
        
        return banner.strip()
    except Exception:
        return ''


# ============================================
# Rate Limiting Helpers
# ============================================

def calculate_delay(rate_limit: int) -> float:
    """
    Calcula delay entre requests baseado em rate limit.
    
    Args:
        rate_limit: Número de requests por segundo
        
    Returns:
        float: Delay em segundos entre cada request
    """
    if rate_limit <= 0:
        return 0.0
    
    return 1.0 / rate_limit


# ============================================
# Conversão de Dados
# ============================================

def bytes_to_human_readable(num_bytes: int) -> str:
    """
    Converte bytes para formato legível (KB, MB, GB).
    
    Args:
        num_bytes: Número de bytes
        
    Returns:
        str: Tamanho formatado
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    
    return f"{num_bytes:.2f} PB"


def ms_to_human_readable(milliseconds: float) -> str:
    """
    Converte milissegundos para formato legível.
    
    Args:
        milliseconds: Tempo em ms
        
    Returns:
        str: Tempo formatado
    """
    if milliseconds < 1000:
        return f"{milliseconds:.2f}ms"
    
    seconds = milliseconds / 1000
    
    if seconds < 60:
        return f"{seconds:.2f}s"
    
    minutes = seconds / 60
    return f"{minutes:.2f}min"