"""
Umbra Scanners - Active Scanning (Port Scanner)
TCP Connect scan, Banner Grabbing e Service Fingerprinting.
"""

import asyncio
import socket
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from core.utils import (
    is_valid_ip,
    is_valid_domain,
    normalize_target,
    generate_trace_id,
    get_timestamp_utc,
    resolve_hostname,
    parse_port_range,
    get_common_ports,
    extract_banner,
    clamp
)
from core.logger import get_logger, LogContext, log_scan_start, log_scan_result


# ============================================
# Configurações
# ============================================

DEFAULT_TIMEOUT = 3
DEFAULT_BANNER_SIZE = 1024
MAX_CONCURRENT_SCANS = 100


# ============================================
# Data Classes
# ============================================

@dataclass
class PortResult:
    """Resultado de scan de uma porta."""
    port: int
    protocol: str = 'tcp'
    state: str = 'closed'
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: float = 0.0
    fingerprint_confidence: float = 0.0
    score: float = 0.0
    error: Optional[str] = None


# ============================================
# Service Fingerprinting (Heurísticas)
# ============================================

# Mapa básico de portas -> serviços comuns
COMMON_SERVICES = {
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    143: 'imap',
    443: 'https',
    445: 'smb',
    465: 'smtps',
    587: 'smtp',
    993: 'imaps',
    995: 'pop3s',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5900: 'vnc',
    6379: 'redis',
    8080: 'http-proxy',
    8443: 'https-alt',
    27017: 'mongodb',
}

# Padrões de banner para fingerprinting
BANNER_PATTERNS = {
    'ssh': [b'SSH-', b'OpenSSH'],
    'http': [b'HTTP/', b'Server:', b'<html', b'<!DOCTYPE'],
    'ftp': [b'220', b'FTP', b'FileZilla'],
    'smtp': [b'220', b'SMTP', b'ESMTP'],
    'mysql': [b'mysql', b'MariaDB'],
    'postgresql': [b'postgres'],
    'redis': [b'Redis'],
    'mongodb': [b'MongoDB'],
    'telnet': [b'Telnet', b'Login:'],
    'vnc': [b'RFB'],
}


def identify_service(port: int, banner: Optional[str]) -> Tuple[Optional[str], float]:
    """
    Identifica serviço baseado em porta e banner.
    
    Args:
        port: Número da porta
        banner: Banner capturado (ou None)
        
    Returns:
        Tuple[service_name, confidence]
    """
    service = None
    confidence = 0.0
    
    # Primeiro: tenta pelo banner
    if banner:
        banner_lower = banner.lower()
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        for svc_name, patterns in BANNER_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in banner_bytes:
                    service = svc_name
                    confidence = 0.9  # Alta confiança por banner match
                    return service, confidence
    
    # Segundo: usa porta comum
    if port in COMMON_SERVICES:
        service = COMMON_SERVICES[port]
        confidence = 0.6 if not banner else 0.3  # Média/baixa confiança
    
    return service, confidence


def calculate_port_score(result: PortResult) -> float:
    """
    Calcula score de risco de uma porta aberta.
    
    Score base:
    - Porta aberta: +0.2
    - Serviço identificado: +0.1
    - Banner exposto: +0.2
    - Porta sensível (22, 3389, 3306, etc): +0.3
    - Alta confiança no fingerprint: +0.1
    
    Args:
        result: PortResult
        
    Returns:
        float: Score entre 0.0 e 2.0
    """
    if result.state != 'open':
        return 0.0
    
    score = 0.2  # Base por porta aberta
    
    # Serviço identificado
    if result.service:
        score += 0.1
    
    # Banner exposto
    if result.banner:
        score += 0.2
    
    # Portas sensíveis
    sensitive_ports = [22, 23, 3389, 3306, 5432, 1433, 27017, 6379, 5900]
    if result.port in sensitive_ports:
        score += 0.3
    
    # Alta confiança no fingerprint
    if result.fingerprint_confidence >= 0.8:
        score += 0.1
    
    return clamp(score, 0.0, 2.0)


# ============================================
# TCP Connect Scan
# ============================================

async def scan_tcp_port(
    host: str,
    port: int,
    timeout: int = DEFAULT_TIMEOUT,
    grab_banner: bool = True
) -> PortResult:
    """
    Escaneia uma porta TCP usando connect scan.
    
    Args:
        host: IP ou hostname
        port: Porta a escanear
        timeout: Timeout em segundos
        grab_banner: Se True, tenta capturar banner
        
    Returns:
        PortResult com informações da porta
    """
    result = PortResult(port=port, protocol='tcp')
    start_time = time.time()
    
    try:
        # Tenta conectar
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        
        result.state = 'open'
        result.response_time_ms = (time.time() - start_time) * 1000
        
        # Tenta capturar banner se porta estiver aberta
        if grab_banner:
            try:
                # Aguarda dados por um tempo curto
                banner_data = await asyncio.wait_for(
                    reader.read(DEFAULT_BANNER_SIZE),
                    timeout=2.0
                )
                
                if banner_data:
                    result.banner = extract_banner(banner_data)
            
            except asyncio.TimeoutError:
                # Alguns serviços não enviam banner automaticamente
                # Tenta enviar probe genérico
                try:
                    writer.write(b'\r\n')
                    await writer.drain()
                    
                    banner_data = await asyncio.wait_for(
                        reader.read(DEFAULT_BANNER_SIZE),
                        timeout=1.0
                    )
                    
                    if banner_data:
                        result.banner = extract_banner(banner_data)
                
                except:
                    pass  # Ignora se falhar
            
            except Exception:
                pass  # Ignora erros de banner grab
            
            finally:
                writer.close()
                await writer.wait_closed()
        
        # Identifica serviço
        result.service, result.fingerprint_confidence = identify_service(
            port, result.banner
        )
        
        # Calcula score
        result.score = calculate_port_score(result)
    
    except asyncio.TimeoutError:
        result.state = 'filtered'  # Timeout pode indicar firewall
        result.error = 'timeout'
    
    except ConnectionRefusedError:
        result.state = 'closed'
        result.error = 'connection_refused'
    
    except Exception as e:
        result.state = 'error'
        result.error = str(e)
    
    return result


# ============================================
# Batch Scanner (com rate limiting)
# ============================================

async def scan_ports(
    host: str,
    ports: List[int],
    timeout: int = DEFAULT_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT_SCANS,
    grab_banner: bool = True,
    trace_id: Optional[str] = None
) -> List[PortResult]:
    """
    Escaneia múltiplas portas de forma assíncrona com rate limiting.
    
    Args:
        host: IP ou hostname
        ports: Lista de portas
        timeout: Timeout por porta
        max_concurrent: Máximo de scans simultâneos
        grab_banner: Se True, captura banners
        trace_id: ID de rastreamento
        
    Returns:
        Lista de PortResult
    """
    logger = get_logger(trace_id=trace_id)
    
    # Semáforo para limitar concorrência
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_semaphore(port: int) -> PortResult:
        async with semaphore:
            logger.debug('scanning_port', host=host, port=port)
            return await scan_tcp_port(host, port, timeout, grab_banner)
    
    # Executa scans em paralelo (mas limitados pelo semáforo)
    tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filtra exceções
    valid_results = []
    for result in results:
        if isinstance(result, Exception):
            logger.warning('port_scan_exception', error=str(result))
        else:
            valid_results.append(result)
    
    return valid_results


# ============================================
# Active Scan Completo (Orquestrador)
# ============================================

async def active_scan(
    target: str,
    ports: Optional[List[int]] = None,
    port_range: Optional[str] = None,
    fast_mode: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT_SCANS,
    grab_banner: bool = True,
    trace_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Realiza port scan completo de um alvo.
    
    Args:
        target: IP ou domínio
        ports: Lista específica de portas (opcional)
        port_range: Range de portas como string (ex: "1-1000")
        fast_mode: Se True, escaneia apenas top 100 portas
        timeout: Timeout por porta
        max_concurrent: Máximo de scans simultâneos
        grab_banner: Se True, captura banners
        trace_id: ID de rastreamento
        
    Returns:
        Dict com resultados no formato padrão
    """
    if not trace_id:
        trace_id = generate_trace_id()
    
    logger = get_logger(trace_id=trace_id)
    start_time = time.time()
    
    # Normaliza target
    normalized = normalize_target(target)
    
    if not normalized['valid']:
        logger.error('active_scan_invalid_target', target=target)
        return {
            'error': 'Invalid target',
            'target': target,
            'trace_id': trace_id
        }
    
    # Resolve hostname se necessário
    host = normalized.get('ip')
    if not host and normalized.get('domain'):
        host = resolve_hostname(normalized['domain'])
        if not host:
            return {
                'error': 'Could not resolve hostname',
                'target': target,
                'trace_id': trace_id
            }
    
    # Determina portas a escanear
    if fast_mode:
        ports_to_scan = get_common_ports('top100')
    elif ports:
        ports_to_scan = ports
    elif port_range:
        ports_to_scan = parse_port_range(port_range)
    else:
        ports_to_scan = get_common_ports('top1000')
    
    log_scan_start(
        logger,
        target=target,
        scan_type='active_scan/port_scan',
        config={
            'host': host,
            'ports_count': len(ports_to_scan),
            'timeout': timeout,
            'max_concurrent': max_concurrent,
            'grab_banner': grab_banner
        }
    )
    
    # Executa scan
    logger.info('port_scan_started', host=host, total_ports=len(ports_to_scan))
    
    scan_results = await scan_ports(
        host=host,
        ports=ports_to_scan,
        timeout=timeout,
        max_concurrent=max_concurrent,
        grab_banner=grab_banner,
        trace_id=trace_id
    )
    
    # Filtra apenas portas abertas para o resultado principal
    open_ports = [r for r in scan_results if r.state == 'open']
    
    logger.info(
        'port_scan_completed',
        host=host,
        total_scanned=len(scan_results),
        open_ports=len(open_ports)
    )
    
    # Monta resultado
    result = {
        'target': target,
        'target_ip': host,
        'type': 'recon/active_scan',
        'timestamp': get_timestamp_utc(),
        'trace_id': trace_id,
        'results': [
            {
                'port': r.port,
                'proto': r.protocol,
                'state': r.state,
                'service': r.service,
                'banner': r.banner,
                'response_time_ms': round(r.response_time_ms, 2),
                'fingerprint_confidence': round(r.fingerprint_confidence, 2),
                'score': round(r.score, 2)
            }
            for r in open_ports
        ],
        'meta': {
            'scan_time_s': round(time.time() - start_time, 2),
            'tool_version': 'umbra-recon-0.1.0',
            'ports_scanned': len(ports_to_scan),
            'ports_open': len(open_ports),
            'ports_closed': len([r for r in scan_results if r.state == 'closed']),
            'ports_filtered': len([r for r in scan_results if r.state == 'filtered']),
        }
    }
    
    # Calcula score total
    result['score_total'] = round(
        sum(r.score for r in open_ports),
        2
    )
    
    log_scan_result(logger, target, 'active_scan', result['results'], result['meta']['scan_time_s'])
    
    return result


# ============================================
# Função de Teste
# ============================================

async def test_active_scan():
    """Testa port scanner contra localhost."""
    
    print("\n" + "="*60)
    print("TESTE: Umbra Active Scan (Port Scanner)")
    print("="*60 + "\n")
    
    # Teste 1: Scan rápido no localhost
    print("1. Testando scan rápido em localhost (top 100 portas)...")
    result = await active_scan(
        target='127.0.0.1',
        fast_mode=True,
        timeout=1,
        max_concurrent=50
    )
    
    print(f"   ✓ Portas escaneadas: {result['meta']['ports_scanned']}")
    print(f"   ✓ Portas abertas: {result['meta']['ports_open']}")
    print(f"   ✓ Duração: {result['meta']['scan_time_s']}s")
    print(f"   ✓ Score total: {result.get('score_total', 0)}")
    
    if result['results']:
        print("\n   Portas abertas encontradas:")
        for port_result in result['results'][:5]:
            print(f"     • Porta {port_result['port']}: {port_result['service'] or 'unknown'}")
            if port_result['banner']:
                banner_preview = port_result['banner'][:50]
                print(f"       Banner: {banner_preview}...")
    
    print("\n" + "="*60)
    print("TESTE COMPLETO!")
    print("="*60 + "\n")


if __name__ == '__main__':
    asyncio.run(test_active_scan())