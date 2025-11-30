"""
Umbra Scanners - Structured Logging
Sistema de logging com trace_id, níveis estruturados e output colorido.
"""

import sys
import logging
from pathlib import Path
from typing import Optional, Any, Dict
from datetime import datetime, timezone
import structlog
from colorama import Fore, Style, init as colorama_init

# Inicializa colorama para Windows
colorama_init(autoreset=True)


# ============================================
# Configuração de Cores por Nível
# ============================================

LOG_COLORS = {
    'debug': Fore.CYAN,
    'info': Fore.GREEN,
    'warning': Fore.YELLOW,
    'error': Fore.RED,
    'critical': Fore.RED + Style.BRIGHT,
}


# ============================================
# Processor Customizado para Structlog
# ============================================

def add_timestamp(logger, method_name, event_dict):
    """Adiciona timestamp UTC no formato ISO 8601."""
    event_dict['timestamp'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return event_dict


def add_log_level(logger, method_name, event_dict):
    """Adiciona nível do log."""
    event_dict['level'] = method_name.upper()
    return event_dict


def add_trace_id(logger, method_name, event_dict):
    """Adiciona trace_id se disponível no contexto."""
    if 'trace_id' not in event_dict:
        # Se não tem trace_id, deixa vazio para ser preenchido pela aplicação
        event_dict['trace_id'] = None
    return event_dict


def colorize_output(logger, method_name, event_dict):
    """Adiciona cores ao output do console."""
    level = event_dict.get('level', 'INFO').lower()
    color = LOG_COLORS.get(level, Fore.WHITE)
    
    # Formata a mensagem com cores
    if sys.stdout.isatty():  
        event_dict['_color'] = color
    
    return event_dict


# ============================================
# Setup do Logger
# ============================================

def setup_logger(
    name: str = 'umbra',
    level: str = 'INFO',
    log_file: Optional[Path] = None,
    json_format: bool = False
) -> structlog.BoundLogger:
    """
    Configura e retorna um logger estruturado.
    
    Args:
        name: Nome do logger
        level: Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path para arquivo de log (opcional)
        json_format: Se True, usa formato JSON; se False, formato legível
        
    Returns:
        structlog.BoundLogger: Logger configurado
    """
    
    # Configura nível
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configura handlers
    handlers = []
    
    # Handler para console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    handlers.append(console_handler)
    
    # Handler para arquivo (se especificado)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(log_level)
        handlers.append(file_handler)
    
    # Configura logging básico
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=handlers,
    )
    
    # Configura processors do structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        add_timestamp,
        add_log_level,
        add_trace_id,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    # Adiciona processador de output apropriado
    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(colorize_output)
        processors.append(
            structlog.dev.ConsoleRenderer(
                colors=sys.stdout.isatty(),
                exception_formatter=structlog.dev.plain_traceback,
            )
        )
    
    # Configura structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger(name)


# ============================================
# Logger Global (Singleton)
# ============================================

_global_logger: Optional[structlog.BoundLogger] = None


def get_logger(
    name: str = 'umbra',
    trace_id: Optional[str] = None,
    **kwargs
) -> structlog.BoundLogger:
    """
    Retorna o logger global ou cria um novo.
    
    Args:
        name: Nome do logger
        trace_id: ID de rastreamento para correlação
        **kwargs: Contexto adicional para bind
        
    Returns:
        structlog.BoundLogger: Logger configurado
    """
    global _global_logger
    
    if _global_logger is None:
        _global_logger = setup_logger(name=name)
    
    # Faz bind com trace_id e contexto adicional
    context = {}
    if trace_id:
        context['trace_id'] = trace_id
    
    context.update(kwargs)
    
    if context:
        return _global_logger.bind(**context)
    
    return _global_logger


# ============================================
# Context Manager para Trace ID
# ============================================

class LogContext:
    """
    Context manager para adicionar trace_id automaticamente aos logs.
    
    Exemplo:
        with LogContext(trace_id='abc-123'):
            logger.info('mensagem')  # Vai incluir trace_id='abc-123'
    """
    
    def __init__(self, trace_id: Optional[str] = None, **kwargs):
        """
        Args:
            trace_id: ID de rastreamento
            **kwargs: Contexto adicional
        """
        self.context = kwargs
        if trace_id:
            self.context['trace_id'] = trace_id
        
        self.token = None
    
    def __enter__(self):
        """Entra no contexto e adiciona variáveis."""
        if self.context:
            self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Sai do contexto e limpa variáveis."""
        if self.token:
            structlog.contextvars.unbind_contextvars(*self.context.keys())
        return False


# ============================================
# Helpers de Logging
# ============================================

def log_scan_start(
    logger: structlog.BoundLogger,
    target: str,
    scan_type: str,
    config: Dict[str, Any]
):
    """
    Log padronizado para início de scan.
    
    Args:
        logger: Logger instance
        target: Alvo do scan
        scan_type: Tipo de scan (port_scan, http_enum, etc)
        config: Configurações do scan
    """
    logger.info(
        'scan_started',
        target=target,
        scan_type=scan_type,
        config=config
    )


def log_scan_result(
    logger: structlog.BoundLogger,
    target: str,
    scan_type: str,
    results: Dict[str, Any],
    duration: float
):
    """
    Log padronizado para resultado de scan.
    
    Args:
        logger: Logger instance
        target: Alvo do scan
        scan_type: Tipo de scan
        results: Resultados obtidos
        duration: Duração em segundos
    """
    logger.info(
        'scan_completed',
        target=target,
        scan_type=scan_type,
        results_count=len(results) if isinstance(results, (list, dict)) else 1,
        duration_s=round(duration, 2)
    )


def log_scan_error(
    logger: structlog.BoundLogger,
    target: str,
    scan_type: str,
    error: Exception,
    context: Optional[Dict[str, Any]] = None
):
    """
    Log padronizado para erro em scan.
    
    Args:
        logger: Logger instance
        target: Alvo do scan
        scan_type: Tipo de scan
        error: Exceção capturada
        context: Contexto adicional
    """
    log_data = {
        'target': target,
        'scan_type': scan_type,
        'error_type': type(error).__name__,
        'error_message': str(error),
    }
    
    if context:
        log_data.update(context)
    
    logger.error('scan_failed', **log_data, exc_info=True)


def log_rate_limit(
    logger: structlog.BoundLogger,
    target: str,
    delay: float,
    reason: str = 'rate_limit'
):
    """
    Log padronizado para rate limiting.
    
    Args:
        logger: Logger instance
        target: Alvo afetado
        delay: Tempo de espera em segundos
        reason: Razão do delay
    """
    logger.debug(
        'rate_limit_applied',
        target=target,
        delay_s=round(delay, 2),
        reason=reason
    )


def log_fingerprint_match(
    logger: structlog.BoundLogger,
    target: str,
    service: str,
    version: Optional[str] = None,
    confidence: float = 0.0,
    method: str = 'banner'
):
    """
    Log padronizado para match de fingerprinting.
    
    Args:
        logger: Logger instance
        target: Alvo scaneado
        service: Serviço identificado
        version: Versão identificada (opcional)
        confidence: Confiança (0.0 a 1.0)
        method: Método usado (banner, tls, http, etc)
    """
    logger.info(
        'fingerprint_match',
        target=target,
        service=service,
        version=version,
        confidence=round(confidence, 2),
        method=method
    )


# ============================================
# Decorator para Auto-Logging
# ============================================

def log_function_call(func):
    """
    Decorator que loga entrada e saída de funções automaticamente.
    
    Exemplo:
        @log_function_call
        def scan_port(target, port):
            ...
    """
    def wrapper(*args, **kwargs):
        logger = get_logger()
        
        func_name = func.__name__
        
        # Log de entrada
        logger.debug(
            f'{func_name}_called',
            function=func_name,
            args=args[:3] if len(args) > 3 else args,  # Limita args no log
            kwargs=kwargs
        )
        
        try:
            # Executa função
            result = func(*args, **kwargs)
            
            # Log de sucesso
            logger.debug(
                f'{func_name}_completed',
                function=func_name,
                result_type=type(result).__name__
            )
            
            return result
        
        except Exception as e:
            # Log de erro
            logger.error(
                f'{func_name}_failed',
                function=func_name,
                error=str(e),
                exc_info=True
            )
            raise
    
    return wrapper


# ============================================
# Função de Teste
# ============================================

def test_logger():
    """
    Testa todas as funcionalidades do logger.
    """
    from core.utils import generate_trace_id
    
    print("\n=== Teste do Logger Umbra ===\n")
    
    # Cria logger
    logger = get_logger(name='umbra_test')
    
    # Gera trace_id
    trace_id = generate_trace_id()
    
    # Testa logs com trace_id
    with LogContext(trace_id=trace_id, module='test'):
        logger.debug('Teste de log DEBUG')
        logger.info('Teste de log INFO', target='example.com')
        logger.warning('Teste de log WARNING', threshold=0.8)
        logger.error('Teste de log ERROR', error_code='E001')
        
        # Testa helpers
        log_scan_start(
            logger,
            target='192.168.1.1',
            scan_type='port_scan',
            config={'ports': [80, 443], 'timeout': 3}
        )
        
        log_scan_result(
            logger,
            target='192.168.1.1',
            scan_type='port_scan',
            results=[{'port': 80, 'state': 'open'}],
            duration=2.5
        )
        
        log_fingerprint_match(
            logger,
            target='192.168.1.1',
            service='nginx',
            version='1.18.0',
            confidence=0.85,
            method='banner'
        )
    
    print("\n=== Teste Completo ===\n")


if __name__ == '__main__':
    test_logger()