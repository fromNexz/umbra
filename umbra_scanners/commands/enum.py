"""
Umbra Scanners - Comando: enum
HTTP enumeration (diretórios, endpoints).
"""

import click
from rich.console import Console

console = Console()


@click.command(name='enum')
@click.argument('url')
@click.option(
    '--wordlist', '-w',
    type=click.Path(exists=True),
    help='Wordlist para brute force'
)
@click.option(
    '--threads',
    type=int,
    default=10,
    help='Número de threads (padrão: 10)'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    help='Salva resultado em arquivo JSON'
)
@click.pass_context
def enum_cmd(ctx, url, wordlist, threads, output):
    """
    Realiza enumeração HTTP (diretórios, arquivos).
    
    URL deve ser completa (ex: http://example.com).
    
    Exemplos:
    
      umbra enum http://localhost:8080
      
      umbra enum http://site.com --wordlist common.txt
      
    [NOTA: Este módulo será implementado em breve]
    """
    
    console.print()
    console.print("[yellow]⚠️  Módulo 'enum' ainda não implementado.[/yellow]")
    console.print("[dim]Você pode implementá-lo em: enumeration/http_enum.py[/dim]")
    console.print()
    console.print("[cyan]Parâmetros recebidos:[/cyan]")
    console.print(f"  • URL: {url}")
    if wordlist:
        console.print(f"  • Wordlist: {wordlist}")
    console.print(f"  • Threads: {threads}")
    if output:
        console.print(f"  • Output: {output}")
    console.print()