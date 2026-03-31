#!/usr/bin/env python3
"""
IKE-CAZADOR - VPN Group ID Discovery Tool
Version 1.0.0

Discovers valid VPN Group IDs through IKE Aggressive Mode enumeration
with robust false positive detection.
"""

import sys
import os
import argparse
import time

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from ike_cazador import (
    IKETester,
    Scanner,
    Validator,
    OutputHandler,
    Config,
)


def check_root_privileges():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("[!] Error: This tool requires root privileges")
        print("[!] ike-scan needs raw socket access for IKE testing")
        print("[!] Please run again with sudo:")
        print(f"    sudo {' '.join(sys.argv)}")
        sys.exit(1)


def check_tmux_session():
    """Check if running in tmux and warn if not"""
    in_tmux = os.environ.get('TMUX') is not None
    
    if not in_tmux:
        print("[!] Warning: Not running in tmux/screen session")
        print("[!] This scan may take 10-20+ minutes depending on options")
        print("[!] Consider running in tmux to avoid interruption")
        print()
        response = input("Continue anyway? [Y/n]: ").strip().lower()
        if response == 'n':
            print("[*] Exiting. Run in tmux with:")
            print(f"    tmux new -s ike-cazador")
            print(f"    sudo {' '.join(sys.argv)}")
            sys.exit(0)
        print()
    else:
        try:
            tmux_session = os.popen("tmux display-message -p '#S'").read().strip()
            print(f"[i] Running in tmux session: {tmux_session}\n")
        except:
            pass


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='IKE-CAZADOR - VPN Group ID Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s 192.168.1.1
  sudo %(prog)s targets.txt custom_wordlist.txt
  sudo %(prog)s targets.txt -j -r -p 4500
  sudo %(prog)s 192.168.1.1 -v

Default wordlist: wordlists/group-id-wordlist.txt (450 Group IDs)
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP, hostname, or file with targets (one per line)'
    )
    
    parser.add_argument(
        'wordlist',
        nargs='?',
        default='wordlists/group-id-wordlist.txt',
        help='Group ID wordlist (default: bundled wordlist)'
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=500,
        help='Destination port (default: 500)'
    )
    
    parser.add_argument(
        '-j', '--jitter',
        action='store_true',
        help='Enable jitter timing for stealth (500ms ±200ms)'
    )
    
    parser.add_argument(
        '-r', '--rotate',
        action='store_true',
        help='Round-robin mode (rotate between targets)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (minimal output)'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='ike-scan timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.quiet and args.verbose:
        parser.error("Cannot use --quiet and --verbose together")
    
    return args


def run_phase1(config, ike_tester, output):
    """Execute Phase 1: Group ID Discovery"""
    # Display configuration
    output.display_config(config)
    
    # Initialize components
    validator = Validator(ike_tester, output)
    scanner = Scanner(ike_tester, validator, output, config)
    
    # Run scan
    start_time = time.time()
    results = scanner.scan(config.targets, config.wordlist)
    scan_time = time.time() - start_time
    
    # Display summary
    output.display_phase1_summary(results, scan_time)
    
    return results


def run_phase2(config, results, ike_tester, output):
    """Execute Phase 2: PSK Hash Capture"""
    print()
    
    # Display commands
    output.display_phase2_commands(results, config.port)
    
    # Prompt user
    response = input("Would you like this tool to run these commands automatically? [Y/n]: ").strip().lower()
    
    if response == 'n':
        print("\n[*] Phase 2 skipped. Commands shown above for manual execution.")
        print(f"[*] All results saved to: {config.session_dir}/")
        return
    
    # Automatic PSK capture
    print()
    for target, group_ids in results.valid.items():
        for group_id, _ in group_ids:
            output.display_psk_capture_start(target, group_id, config.port)
            
            # Capture PSK
            result = ike_tester.capture_psk(target, group_id, port=config.port)
            
            # Save to file
            output_file = f"{config.session_dir}/{target}_{group_id}.txt"
            with open(output_file, 'w') as f:
                if result.raw_output:
                    f.write(result.raw_output)
            
            # Update results with Phase 2 data (transform set)
            for i, (gid, ike_result) in enumerate(results.valid[target]):
                if gid == group_id:
                    # Update with Phase 2 capture data
                    results.valid[target][i] = (gid, result)
                    break
            
            # Display result
            output.display_psk_capture_result(target, group_id, result)
    
    # Display Phase 2 summary with hashcat commands
    output.display_phase2_summary(results)


def main():
    """Main entry point"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Startup checks
        check_root_privileges()
        check_tmux_session()
        
        # Create configuration
        try:
            config = Config(args)
        except FileNotFoundError as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
        except ValueError as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
        
        # Initialize IKE tester
        try:
            ike_tester = IKETester(timeout=args.timeout)
        except FileNotFoundError as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
        
        # Initialize output handler
        output = OutputHandler(
            config.session_dir,
            verbose=args.verbose,
            quiet=args.quiet,
            use_color=not args.no_color
        )
        
        # Display banner
        output.display_banner()
        
        # Phase 1: Group ID Discovery
        results = run_phase1(config, ike_tester, output)
        
        # Phase 2: PSK Capture (if valid IDs found)
        if results.has_valid_ids():
            run_phase2(config, results, ike_tester, output)
        else:
            print(f"\n{output.c.YELLOW}[*] No valid Group IDs found{output.c.RESET}")
            print("\nSuggestions:")
            print("  - Try a different wordlist with company-specific terms")
            print("  - Use wordlist mutation tools (john, hashcat rules)")
            print("  - Manually test known patterns")
        
        # Close log files
        output.close()
        
        print(f"\n[*] Scan complete. All logs saved to: {output.c.CYAN}{config.session_dir}/{output.c.RESET}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
