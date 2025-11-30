"""
Script para abrir múltiplas portas para teste do Umbra Scanner.
"""

import socket
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler


def start_http_server(port):
    """Inicia servidor HTTP em uma porta específica."""
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Silencia logs
    
    try:
        server = HTTPServer(('127.0.0.1', port), QuietHandler)
        print(f"✓ HTTP Server rodando na porta {port}")
        server.serve_forever()
    except Exception as e:
        print(f"✗ Erro na porta {port}: {e}")


def start_tcp_listener(port, banner=None):
    """Inicia um listener TCP simples em uma porta."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))
        sock.listen(5)
        print(f"✓ TCP Listener rodando na porta {port}")
        
        while True:
            conn, addr = sock.accept()
            if banner:
                conn.send(banner.encode())
            time.sleep(0.1)
            conn.close()
    except Exception as e:
        print(f"✗ Erro na porta {port}: {e}")


def main():
    print("\n" + "="*60)
    print("🔧 Umbra Test Server - Abrindo portas para teste")
    print("="*60 + "\n")
    
    # Lista de serviços a simular
    services = [
        # HTTP Servers
        (start_http_server, 8080, None),
        (start_http_server, 8000, None),
        (start_http_server, 3000, None),
        
        # Simulação de serviços com banners
        (start_tcp_listener, 2222, "SSH-2.0-TestSSH_1.0\r\n"),
        (start_tcp_listener, 3306, "MySQL Server 5.7.0\r\n"),
        (start_tcp_listener, 6379, "Redis 6.0.0\r\n"),
        (start_tcp_listener, 5432, "PostgreSQL 13.0\r\n"),
    ]
    
    threads = []
    
    # Inicia cada serviço em uma thread separada
    for func, port, *args in services:
        thread = threading.Thread(
            target=func,
            args=(port, *args),
            daemon=True
        )
        thread.start()
        threads.append(thread)
        time.sleep(0.1)
    
    print("\n" + "="*60)
    print("✓ Todos os serviços iniciados!")
    print("="*60)
    print("\nPortas abertas:")
    print("  • 8080, 8000, 3000  → HTTP Servers")
    print("  • 2222              → SSH (simulado)")
    print("  • 3306              → MySQL (simulado)")
    print("  • 6379              → Redis (simulado)")
    print("  • 5432              → PostgreSQL (simulado)")
    print("\nAgora você pode escanear:")
    print("  python -m cli scan localhost --ports 8080,3000,2222,3306")
    print("\nPressione Ctrl+C para parar todos os serviços.\n")
    
    try:
        # Mantém o script rodando
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Parando todos os serviços...")
        print("✓ Serviços encerrados.\n")


if __name__ == '__main__':
    main()