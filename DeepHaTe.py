import sys
from Torrent_Table_Sniffer import DHTLiveTable
from Torrent_Raw_Sniffer import DHTSniffer

def main():
    banner = r"""
             ░▒▒░                                                                                                       
            ░▓▓▓░                                                                                                       
           ░▓▓▓░                                                                                                        
           ▓▓▓░                                                                                                         
          ░▓▓▓                                                                                                          
          ░▓▓▒                                                                                                          
          ▒▓▓░                                                                                                          
          ▒▓▓░   ▒▓▓▓▓▓▓░                                                                                               
          ▓▓▓▒  ░▓░░░▓▒▓▓▒                                                                                              
         ░▓▓▓▓░▓▓▒░▒█▓▓▓▓▓                                                                                              
          ▓▓▓▓▓▓░ ░█░▓▓▓▓▓                                                                                              
          ▒▓▓▒▓▓▒▒▒▓▓▓▓▓▓▓                                                                                              
          ▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▒                                                                                              
         ░▓▓▓▓▓░░▓▓▓▓▓▓▓▓░░░░░░      ░░░░░░░  ░░░░░░░  ░░░░░░     ░░░   ░░░    ░░░░░   ░░░░░░░ ░░░░░░░░                 
         ▓▓▓▒▒░░░▒▓▓▓▓▓▓▓░███████▓░ ░███████▒░███████▒░████████▒ ▓███░ ▒███░ ░██████▒ ▒███████▒▓██████▓                 
        ░▓▓▓▒█▓▓▒▓▓▓▓▓▓▒▓▒▒████████▓░███▓░░░░░███▓░░░░░████▓▓███▒▓███▓▓████░ ▒███████░░▓█████▓▒▓███░░░░                 
          ▒▓▓▓▒▓▓▓▒▓▓▓▓▒▓▓░██▓ ░████░███████▒░███████▒░███▓▒▓███▒▓█████████░░███▓ ▓██▓  ▒███▒  ▓██████▓                 
          ▒▓▓▓▓▓▓▓▓▓▓▓▓▒▓▓░████████▓░████░░▒░░███▓░░▒░░████████░ ▓████▓████░▓█████████░ ▒███░  ▓███▒░▒░                 
          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░███████▒ ░███████▓░███████▓░███▓      ▓███░ ▒███░████▓▓▓███▒ ▒███░  ▓███████░                
          ▒▓▓▓▓▓▓▓▓▓▓▓▒▓▓▒░░░░░░     ░░░░░░░░ ░░░░░░░░ ░░░░      ░░░░  ░░░░ ░░░░   ░░░░ ░░░░   ░░░░░░░░                 
      ░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▓▓▒▓                                                                                              
 ░▒▓▓░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░▓░                                                                                        
░▓▓▓▒▒▒▒▒▒▒▓▓▓▓▓▒▒▒▒░░░░░░░░░░░░░                                                                                       
                                                  By Himitsu - "DHT Sniffer - Scanner"                                  
    """
    print(banner)

    if len(sys.argv) < 3:
        print("Use: python DeepHaTe.py [mode] [InfoHash or Torrent File] [--Download]")
        print("Available modes:")
        print(" Table: Synthesized information (Port Scan, GeoLocation)")
        print(" Raw: Raw mode to view unprocessed DHT packets")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]
    download = '--Download' in sys.argv

    if mode == 'Table':
        dht_sniffer = DHTLiveTable()
        dht_sniffer.initialize(target=target, download=download)
    elif mode == 'Raw':
        dht_sniffer = DHTSniffer()
        dht_sniffer.start(target=target, download=download)
    else:
        print("Unrecognized mode. Use 'Table' or 'Raw'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
