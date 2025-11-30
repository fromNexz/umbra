"""
Umbra Scanners - CLI Principal
Entry point para todos os comandos do Umbra.
"""

import click
import sys
from pathlib import Path

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent))

from commands import recon, scan, enum
from core.logger import get_logger

# Configuração global
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version='0.1.0', prog_name='Umbra Scanners')
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Ativa modo verbose (DEBUG logs)'
)
@click.option(
    '--quiet', '-q',
    is_flag=True,
    help='Modo silencioso (apenas erros)'
)
@click.pass_context
def cli(ctx, verbose, quiet):
    """
    🔍 Umbra Scanners - Ferramentas de Reconhecimento e Enumeração
    
    Ferramenta para testar detecção de ataques no Umbra Core.
    
    Exemplos de uso:
    
      umbra recon example.com
      
      umbra scan 192.168.1.1 --ports 80,443
      
      umbra enum http://localhost:8080
    
    Use 'umbra COMANDO --help' para ver opções de cada comando.
    """
    # Configura nível de log baseado nas flags
    if quiet:
        log_level = 'ERROR'
    elif verbose:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'
    
    # Armazena no contexto para os subcomandos usarem
    ctx.ensure_object(dict)
    ctx.obj['log_level'] = log_level
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet


# ============================================
# Registra comandos
# ============================================

cli.add_command(recon.recon_cmd)
cli.add_command(scan.scan_cmd)
cli.add_command(enum.enum_cmd)


# ============================================
# Entry point
# ============================================

def main():
    """Entry point principal."""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        click.echo('\n\n⚠️  Operação cancelada pelo usuário.', err=True)
        sys.exit(130)
    except Exception as e:
        logger = get_logger()
        logger.error('cli_unexpected_error', error=str(e), exc_info=True)
        click.echo(f'\n❌ Erro inesperado: {e}', err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()