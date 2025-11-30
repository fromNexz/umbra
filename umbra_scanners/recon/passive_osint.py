"""
Umbra Scanners - Passive OSINT (Reconnaissance)
Coleta informações públicas sem tocar diretamente no alvo.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import aiohttp
import aiodns
import dns.resolver
import whois as python_whois

from core.utils import (
    is_valid_ip,
    is_valid_domain,
    normalize_target,
    generate_trace_id,
    get_timestamp_utc,
    sanitize_input,
    resolve_hostname,
    reverse_dns
)
from core.logger import get_logger, LogContext, log_scan_start, log_scan_result, log_scan_error


# ============================================
# Configurações Globais
# ============================================

DEFAULT_TIMEOUT = 10
DEFAULT_DNS_SERVERS = ['8.8.8.8', '1.1.1.1']
CACHE_EXPIRY_HOURS = 24


# ============================================
# Cache Simples em Memória
# ============================================

class SimpleCache:
    """Cache em memória com TTL para evitar consultas repetidas."""
    
    def __init__(self, ttl_hours: int = CACHE_EXPIRY_HOURS):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl = timedelta(hours=ttl_hours)
    
    def get(self, key: str) -> Optional[Any]:
        """Recupera item do cache se ainda válido."""
        if key in self.cache:
            entry = self.cache[key]
            if datetime.now() - entry['timestamp'] < self.ttl:
                return entry['data']
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, data: Any):
        """Armazena item no cache."""
        self.cache[key] = {
            'timestamp': datetime.now(),
            'data': data
        }
    
    def clear(self):
        """Limpa todo o cache."""
        self.cache.clear()


# Cache global
_cache = SimpleCache()


# ============================================
# Whois Lookup
# ============================================

async def whois_lookup(domain: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
    """
    Realiza Whois lookup de um domínio.
    
    Args:
        domain: Domínio a consultar
        use_cache: Se True, usa cache
        
    Returns:
        Dict com informações Whois ou None se falhar
    """
    logger = get_logger()
    
    if not is_valid_domain(domain):
        logger.warning('whois_invalid_domain', domain=domain)
        return None
    
    cache_key = f'whois:{domain}'
    
    # Verifica cache
    if use_cache:
        cached = _cache.get(cache_key)
        if cached:
            logger.debug('whois_cache_hit', domain=domain)
            return cached
    
    try:
        # Executa Whois (blocking, então rodamos em executor)
        loop = asyncio.get_event_loop()
        whois_data = await loop.run_in_executor(None, python_whois.whois, domain)
        
        if whois_data:
            result = {
                'domain': domain,
                'registrar': getattr(whois_data, 'registrar', None),
                'creation_date': str(getattr(whois_data, 'creation_date', None)),
                'expiration_date': str(getattr(whois_data, 'expiration_date', None)),
                'updated_date': str(getattr(whois_data, 'updated_date', None)),
                'name_servers': getattr(whois_data, 'name_servers', []),
                'status': getattr(whois_data, 'status', []),
                'emails': getattr(whois_data, 'emails', []),
                'org': getattr(whois_data, 'org', None),
                'country': getattr(whois_data, 'country', None),
            }
            
            # Armazena no cache
            _cache.set(cache_key, result)
            
            logger.info('whois_success', domain=domain, registrar=result.get('registrar'))
            return result
        
    except Exception as e:
        logger.warning('whois_failed', domain=domain, error=str(e))
    
    return None


# ============================================
# DNS Records
# ============================================

async def dns_lookup(
    domain: str,
    record_types: List[str] = None,
    use_cache: bool = True
) -> Dict[str, List[str]]:
    """
    Realiza lookup de múltiplos tipos de DNS records.
    
    Args:
        domain: Domínio a consultar
        record_types: Lista de tipos (A, AAAA, MX, NS, TXT, CNAME, SOA)
        use_cache: Se True, usa cache
        
    Returns:
        Dict com {tipo: [valores]}
    """
    logger = get_logger()
    
    if not is_valid_domain(domain):
        logger.warning('dns_invalid_domain', domain=domain)
        return {}
    
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    cache_key = f'dns:{domain}:{",".join(sorted(record_types))}'
    
    # Verifica cache
    if use_cache:
        cached = _cache.get(cache_key)
        if cached:
            logger.debug('dns_cache_hit', domain=domain)
            return cached
    
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_TIMEOUT
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
            logger.debug('dns_record_found', domain=domain, type=record_type, count=len(results[record_type]))
        
        except dns.resolver.NoAnswer:
            results[record_type] = []
        
        except dns.resolver.NXDOMAIN:
            logger.warning('dns_nxdomain', domain=domain)
            break
        
        except Exception as e:
            logger.debug('dns_lookup_error', domain=domain, type=record_type, error=str(e))
            results[record_type] = []
    
    # Armazena no cache
    _cache.set(cache_key, results)
    
    return results


# ============================================
# Reverse DNS Lookup (Async)
# ============================================

async def reverse_dns_lookup(ip: str, use_cache: bool = True) -> Optional[str]:
    """
    Realiza reverse DNS lookup assíncrono.
    
    Args:
        ip: Endereço IP
        use_cache: Se True, usa cache
        
    Returns:
        Hostname ou None
    """
    logger = get_logger()
    
    if not is_valid_ip(ip):
        logger.warning('reverse_dns_invalid_ip', ip=ip)
        return None
    
    cache_key = f'rdns:{ip}'
    
    # Verifica cache
    if use_cache:
        cached = _cache.get(cache_key)
        if cached:
            logger.debug('reverse_dns_cache_hit', ip=ip)
            return cached
    
    try:
        # Usa função síncrona do utils em executor
        loop = asyncio.get_event_loop()
        hostname = await loop.run_in_executor(None, reverse_dns, ip)
        
        if hostname:
            _cache.set(cache_key, hostname)
            logger.info('reverse_dns_success', ip=ip, hostname=hostname)
            return hostname
    
    except Exception as e:
        logger.debug('reverse_dns_failed', ip=ip, error=str(e))
    
    return None


# ============================================
# Certificate Transparency Logs (crt.sh)
# ============================================

async def crtsh_lookup(domain: str, timeout: int = DEFAULT_TIMEOUT) -> List[str]:
    """
    Busca subdomínios via Certificate Transparency Logs (crt.sh).
    
    Args:
        domain: Domínio base
        timeout: Timeout em segundos
        
    Returns:
        Lista de subdomínios encontrados
    """
    logger = get_logger()
    
    if not is_valid_domain(domain):
        logger.warning('crtsh_invalid_domain', domain=domain)
        return []
    
    url = f'https://crt.sh/?q=%.{domain}&output=json'
    subdomains = set()
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Separa por \n (crt.sh retorna múltiplos nomes assim)
                        names = name_value.split('\n')
                        
                        for name in names:
                            name = name.strip().lower()
                            # Remove wildcards
                            if name.startswith('*.'):
                                name = name[2:]
                            
                            # Adiciona se for subdomínio válido
                            if name and name.endswith(domain) and is_valid_domain(name):
                                subdomains.add(name)
                    
                    logger.info('crtsh_success', domain=domain, subdomains_found=len(subdomains))
                else:
                    logger.warning('crtsh_bad_status', domain=domain, status=response.status)
    
    except asyncio.TimeoutError:
        logger.warning('crtsh_timeout', domain=domain)
    
    except Exception as e:
        logger.warning('crtsh_error', domain=domain, error=str(e))
    
    return sorted(list(subdomains))


# ============================================
# ASN Lookup (via IPinfo.io - free tier)
# ============================================

async def asn_lookup(ip: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    """
    Busca informações de ASN e geolocalização via IPinfo.io.
    
    Args:
        ip: Endereço IP
        timeout: Timeout em segundos
        
    Returns:
        Dict com informações de ASN e geo
    """
    logger = get_logger()
    
    if not is_valid_ip(ip):
        logger.warning('asn_invalid_ip', ip=ip)
        return None
    
    # API pública do IPinfo (sem auth, rate limited)
    url = f'https://ipinfo.io/{ip}/json'
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    result = {
                        'ip': ip,
                        'hostname': data.get('hostname'),
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'country': data.get('country'),
                        'loc': data.get('loc'),  # lat,long
                        'org': data.get('org'),  # ASN + org name
                        'postal': data.get('postal'),
                        'timezone': data.get('timezone'),
                    }
                    
                    logger.info('asn_success', ip=ip, org=result.get('org'))
                    return result
                
                elif response.status == 429:
                    logger.warning('asn_rate_limited', ip=ip)
                
                else:
                    logger.warning('asn_bad_status', ip=ip, status=response.status)
    
    except asyncio.TimeoutError:
        logger.warning('asn_timeout', ip=ip)
    
    except Exception as e:
        logger.warning('asn_error', ip=ip, error=str(e))
    
    return None


# ============================================
# Passive Recon Completo (Orquestrador)
# ============================================

async def passive_recon(
    target: str,
    trace_id: Optional[str] = None,
    include_subdomains: bool = True,
    include_asn: bool = True,
    timeout: int = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    """
    Realiza reconhecimento passivo completo de um alvo.
    
    Args:
        target: IP ou domínio
        trace_id: ID de rastreamento
        include_subdomains: Se True, busca subdomínios via CT logs
        include_asn: Se True, busca informações de ASN
        timeout: Timeout em segundos
        
    Returns:
        Dict com todos os resultados no formato padrão
    """
    if not trace_id:
        trace_id = generate_trace_id()
    
    logger = get_logger(trace_id=trace_id)
    start_time = time.time()
    
    # Normaliza target
    normalized = normalize_target(target)
    
    if not normalized['valid']:
        logger.error('passive_recon_invalid_target', target=target)
        return {
            'error': 'Invalid target',
            'target': target,
            'trace_id': trace_id
        }
    
    target_type = normalized['type']
    domain = normalized.get('domain')
    ip = normalized.get('ip')
    
    log_scan_start(
        logger,
        target=target,
        scan_type='passive_recon',
        config={
            'include_subdomains': include_subdomains,
            'include_asn': include_asn,
            'timeout': timeout
        }
    )
    
    # Inicializa resultado
    result = {
        'target': target,
        'target_type': target_type,
        'type': 'recon/passive',
        'timestamp': get_timestamp_utc(),
        'trace_id': trace_id,
        'results': {},
        'meta': {}
    }
    
    # ============================================
    # Executa consultas em paralelo
    # ============================================
    
    tasks = []
    
    # Se for domínio
    if domain:
        # Whois
        tasks.append(('whois', whois_lookup(domain)))
        
        # DNS records
        tasks.append(('dns', dns_lookup(domain)))
        
        # Resolve para IP
        if not ip:
            ip = resolve_hostname(domain)
            result['results']['resolved_ip'] = ip
        
        # Subdomínios (CT logs)
        if include_subdomains:
            tasks.append(('subdomains', crtsh_lookup(domain, timeout)))
    
    # Se temos IP (direto ou resolvido)
    if ip:
        # Reverse DNS
        tasks.append(('reverse_dns', reverse_dns_lookup(ip)))
        
        # ASN lookup
        if include_asn:
            tasks.append(('asn', asn_lookup(ip, timeout)))
    
    # Aguarda todas as tasks
    task_results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)
    
    # Mapeia resultados
    for (name, _), task_result in zip(tasks, task_results):
        if isinstance(task_result, Exception):
            logger.warning('passive_recon_task_failed', task=name, error=str(task_result))
            result['results'][name] = None
        else:
            result['results'][name] = task_result
    
    # ============================================
    # Calcula score básico
    # ============================================
    
    score = 0.0
    
    # Domínio tem Whois?
    if result['results'].get('whois'):
        score += 0.1
    
    # Tem DNS records?
    dns_records = result['results'].get('dns', {})
    if dns_records:
        score += len([v for v in dns_records.values() if v]) * 0.05
    
    # Tem subdomínios?
    subdomains = result['results'].get('subdomains', [])
    if subdomains:
        score += min(len(subdomains) * 0.02, 0.3)  # Cap em 0.3
    
    # Tem informações de ASN?
    if result['results'].get('asn'):
        score += 0.15
    
    result['score_total'] = round(score, 2)
    
    # ============================================
    # Metadata
    # ============================================
    
    duration = time.time() - start_time
    
    result['meta'] = {
        'scan_time_s': round(duration, 2),
        'tool_version': 'umbra-recon-0.1.0',
        'tasks_completed': len([r for r in task_results if not isinstance(r, Exception)]),
        'tasks_failed': len([r for r in task_results if isinstance(r, Exception)])
    }
    
    log_scan_result(logger, target, 'passive_recon', result['results'], duration)
    
    return result


# ============================================
# Função de Teste
# ============================================

async def test_passive_osint():
    """Testa todas as funcionalidades de OSINT passivo."""
    
    print("\n" + "="*60)
    print("BETA: Umbra Passive OSINT")
    print("="*60 + "\n")
    
    # Teste 1: Whois
    print("1. Testando Whois Lookup...")
    whois_result = await whois_lookup('google.com')
    if whois_result:
        print(f"   ✓ Registrar: {whois_result.get('registrar')}")
        print(f"   ✓ Name Servers: {whois_result.get('name_servers', [])[:2]}")
    
    await asyncio.sleep(1)
    
    # Teste 2: DNS
    print("\n2. Testando DNS Lookup...")
    dns_result = await dns_lookup('google.com', ['A', 'MX', 'NS'])
    for record_type, values in dns_result.items():
        if values:
            print(f"   ✓ {record_type}: {values[:2]}")
    
    await asyncio.sleep(1)
    
    # Teste 3: Reverse DNS
    print("\n3. Testando Reverse DNS...")
    rdns_result = await reverse_dns_lookup('8.8.8.8')
    if rdns_result:
        print(f"   ✓ Hostname: {rdns_result}")
    
    await asyncio.sleep(1)
    
    # Teste 4: Certificate Transparency
    print("\n4. Testando CT Logs (subdomínios)...")
    print("   (isso pode demorar alguns segundos...)")
    crtsh_result = await crtsh_lookup('example.com')
    if crtsh_result:
        print(f"   ✓ Subdomínios encontrados: {len(crtsh_result)}")
        print(f"   ✓ Exemplos: {crtsh_result[:3]}")
    
    await asyncio.sleep(1)
    
    # Teste 5: ASN Lookup
    print("\n5. Testando ASN Lookup...")
    asn_result = await asn_lookup('8.8.8.8')
    if asn_result:
        print(f"   ✓ Org: {asn_result.get('org')}")
        print(f"   ✓ Location: {asn_result.get('city')}, {asn_result.get('country')}")
    
    await asyncio.sleep(1)
    
    # Teste 6: Passive Recon Completo
    print("\n6. Testando Passive Recon Completo...")
    print("   (isso vai combinar todos os métodos...)")
    full_result = await passive_recon(
        'example.com',
        include_subdomains=False,  # Desabilita para ser mais rápido
        include_asn=True
    )
    
    print(f"\n   ✓ Target: {full_result['target']}")
    print(f"   ✓ Score: {full_result.get('score_total', 0)}")
    print(f"   ✓ Duração: {full_result['meta']['scan_time_s']}s")
    print(f"   ✓ Tasks completadas: {full_result['meta']['tasks_completed']}")
    
    # Mostra resultado JSON (apenas primeiros 500 chars)
    print("\n7. Exemplo de Output JSON (truncado):")
    json_output = json.dumps(full_result, indent=2)
    print(json_output[:500] + "...\n")
    
    print("="*60)
    print("TESTE COMPLETO!")
    print("="*60 + "\n")


if __name__ == '__main__':
    asyncio.run(test_passive_osint())