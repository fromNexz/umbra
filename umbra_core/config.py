"""
================================================================================
                    UMBRA CORE - Global Configuration (config.py)
================================================================================
Configuração global do sistema Umbra Core.
Centraliza todas as configurações em um único lugar.
================================================================================
"""

import os
from pathlib import Path
from typing import Set


class UmbraConfig:
    """
    Configuração global do Umbra Core.
    
    Todas as configurações do sistema em um único lugar.
    Pode ser sobrescrita por variáveis de ambiente.
    """
    
    # ========================================================================
    #                          CONFIGURAÇÕES GERAIS
    # ========================================================================
    
    # Nome e versão do sistema
    SYSTEM_NAME = "Umbra Core"
    VERSION = "0.1.0"
    
    # Diretório raiz do projeto
    ROOT_DIR = Path(__file__).parent
    
    # ========================================================================
    #                          LOGGING
    # ========================================================================
    
    # Diretório de logs
    LOG_DIR = os.getenv("UMBRA_LOG_DIR", "logs")
    
    # Tamanho máximo de cada arquivo de log (em bytes)
    LOG_MAX_BYTES = int(os.getenv("UMBRA_LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10MB
    
    # Número de backups de log a manter
    LOG_BACKUP_COUNT = int(os.getenv("UMBRA_LOG_BACKUP_COUNT", 5))
    
    # Habilitar logs no console
    LOG_CONSOLE = os.getenv("UMBRA_LOG_CONSOLE", "true").lower() == "true"
    
    # Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    LOG_LEVEL = os.getenv("UMBRA_LOG_LEVEL", "INFO")
    
    # ========================================================================
    #                          SCORING
    # ========================================================================
    
    # Habilitar cache de scores (melhora performance)
    ENABLE_SCORE_CACHE = os.getenv("UMBRA_SCORE_CACHE", "true").lower() == "true"
    
    # Tamanho máximo do cache de scores
    SCORE_CACHE_SIZE = int(os.getenv("UMBRA_SCORE_CACHE_SIZE", 1000))
    
    # TTL do cache em segundos
    SCORE_CACHE_TTL = int(os.getenv("UMBRA_SCORE_CACHE_TTL", 300))  # 5 minutos
    
    # ========================================================================
    #                          WHITELISTS E BLACKLISTS
    # ========================================================================
    
    # IPs em whitelist (nunca bloqueados)
    WHITELIST_IPS: Set[str] = {
        "127.0.0.1",
        "::1",
        "localhost",
    }
    
    # IPs em blacklist (sempre bloqueados)
    BLACKLIST_IPS: Set[str] = {
              
    }
    
    # Arquivo de whitelist (um IP por linha)
    WHITELIST_FILE = os.getenv("UMBRA_WHITELIST_FILE", "config/whitelist.txt")
    
    # Arquivo de blacklist (um IP por linha)
    BLACKLIST_FILE = os.getenv("UMBRA_BLACKLIST_FILE", "config/blacklist.txt")
    
    # ========================================================================
    #                          POLÍTICAS DE BLOQUEIO
    # ========================================================================
    
    # Duração padrão de bloqueio temporário (em segundos)
    DEFAULT_BLOCK_DURATION = int(os.getenv("UMBRA_BLOCK_DURATION", 3600))  # 1 hora
    
    # Máximo de tentativas antes de bloqueio permanente
    MAX_VIOLATIONS_BEFORE_PERMANENT_BLOCK = int(
        os.getenv("UMBRA_MAX_VIOLATIONS", 5)
    )
    
    # ========================================================================
    #                          PERFORMANCE
    # ========================================================================
    
    # Número máximo de eventos processados simultaneamente
    MAX_CONCURRENT_EVENTS = int(os.getenv("UMBRA_MAX_CONCURRENT", 100))
    
    # Timeout para processamento de um evento (em segundos)
    EVENT_PROCESSING_TIMEOUT = int(os.getenv("UMBRA_EVENT_TIMEOUT", 5))
    
    # ========================================================================
    #                          INTEGRAÇÃO
    # ========================================================================
    
    # Porta da API REST (futuro)
    API_PORT = int(os.getenv("UMBRA_API_PORT", 8000))
    
    # Host da API
    API_HOST = os.getenv("UMBRA_API_HOST", "0.0.0.0")
    
    # Habilitar API REST
    ENABLE_API = os.getenv("UMBRA_ENABLE_API", "false").lower() == "true"
    
    # ========================================================================
    #                          NOTIFICAÇÕES
    # ========================================================================
    
    # Habilitar notificações por email (futuro)
    ENABLE_EMAIL_ALERTS = os.getenv("UMBRA_EMAIL_ALERTS", "false").lower() == "true"
    
    # Email do administrador
    ADMIN_EMAIL = os.getenv("UMBRA_ADMIN_EMAIL", "admin@example.com")
    
    # ========================================================================
    #                          HONEYPOT
    # ========================================================================
    
    # URL do honeypot para redirecionamento
    HONEYPOT_URL = os.getenv("UMBRA_HONEYPOT_URL", "http://honeypot.internal")
    
    # Habilitar honeypot
    ENABLE_HONEYPOT = os.getenv("UMBRA_ENABLE_HONEYPOT", "false").lower() == "true"
    
    # ========================================================================
    #                          MÉTODOS AUXILIARES
    # ========================================================================
    
    @classmethod
    def load_ip_list_from_file(cls, filepath: str) -> Set[str]:
        """
        Carrega lista de IPs de um arquivo.
        
        Args:
            filepath: Caminho do arquivo
            
        Returns:
            Set com os IPs
        """
        ips = set()
        path = Path(filepath)
        
        if not path.exists():
            return ips
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.add(line)
        
        return ips
    
    @classmethod
    def load_whitelists_and_blacklists(cls):
        """Carrega whitelists e blacklists de arquivos"""
        # Carrega whitelist
        file_whitelist = cls.load_ip_list_from_file(cls.WHITELIST_FILE)
        cls.WHITELIST_IPS.update(file_whitelist)
        
        # Carrega blacklist
        file_blacklist = cls.load_ip_list_from_file(cls.BLACKLIST_FILE)
        cls.BLACKLIST_IPS.update(file_blacklist)
    
    @classmethod
    def get_config_summary(cls) -> dict:
        """Retorna um resumo das configurações"""
        return {
            'system': {
                'name': cls.SYSTEM_NAME,
                'version': cls.VERSION,
            },
            'logging': {
                'directory': cls.LOG_DIR,
                'max_bytes': cls.LOG_MAX_BYTES,
                'backup_count': cls.LOG_BACKUP_COUNT,
                'console_enabled': cls.LOG_CONSOLE,
                'level': cls.LOG_LEVEL,
            },
            'scoring': {
                'cache_enabled': cls.ENABLE_SCORE_CACHE,
                'cache_size': cls.SCORE_CACHE_SIZE,
                'cache_ttl': cls.SCORE_CACHE_TTL,
            },
            'security': {
                'whitelist_size': len(cls.WHITELIST_IPS),
                'blacklist_size': len(cls.BLACKLIST_IPS),
                'default_block_duration': cls.DEFAULT_BLOCK_DURATION,
                'max_violations': cls.MAX_VIOLATIONS_BEFORE_PERMANENT_BLOCK,
            },
            'performance': {
                'max_concurrent_events': cls.MAX_CONCURRENT_EVENTS,
                'event_timeout': cls.EVENT_PROCESSING_TIMEOUT,
            },
            'integrations': {
                'api_enabled': cls.ENABLE_API,
                'api_host': cls.API_HOST,
                'api_port': cls.API_PORT,
                'honeypot_enabled': cls.ENABLE_HONEYPOT,
            },
        }


# ============================================================================
#                          INICIALIZAÇÃO
# ============================================================================

# Carrega whitelists/blacklists ao importar o módulo
UmbraConfig.load_whitelists_and_blacklists()


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    import json
    
    print("=" * 80)
    print("UMBRA CORE - Configuração Global")
    print("=" * 80)
    print()
    
    config_summary = UmbraConfig.get_config_summary()
    print(json.dumps(config_summary, indent=2))
    print()
    
    print(f"📁 Diretório de logs: {UmbraConfig.LOG_DIR}")
    print(f"📊 Cache habilitado: {UmbraConfig.ENABLE_SCORE_CACHE}")
    print(f"🛡️  IPs em whitelist: {len(UmbraConfig.WHITELIST_IPS)}")
    print(f"🚫 IPs em blacklist: {len(UmbraConfig.BLACKLIST_IPS)}")
    print()
    
    print("✅ Configuração carregada com sucesso!")