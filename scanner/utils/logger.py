import colorama
from colorama import Fore, Style
import sys

# Initialize Colorama
colorama.init(autoreset=True)

class Logger:
    @staticmethod
    def info(message):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")

    @staticmethod
    def success(message):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")

    @staticmethod
    def warning(message):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

    @staticmethod
    def error(message):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}", file=sys.stderr)

    @staticmethod
    def critical(message):
        print(f"{Fore.WHITE}{Style.BRIGHT}{colorama.Back.RED}[CRITICAL]{Style.RESET_ALL} {message}", file=sys.stderr)

    @staticmethod
    def vulns(message, severity='INFO'):
        color_map = {
            'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
            'HIGH': Fore.RED + Style.BRIGHT,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN,
            'INFO': Fore.CYAN
        }
        color = color_map.get(severity, Fore.WHITE)
        print(f"{color}[{severity}]{Style.RESET_ALL} {message}")
