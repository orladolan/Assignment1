
# Imports
import sys

# Variables
help_shown = False     # To track if help has been shown


def help():
    #Help Feature - prints out instructions 

    usage_text = """
    Network Reconnaissance Tool

    How To Use:

    Options:
      -p or --passive:    Listen for traffic at the interface
      -h or --help:       Show a help message and exit
      -e or --exit:       Exit the program
    """
  
    print(usage_text)

# Seperate function for processing args for readability
# Individually goes through the valid inputs and determines what to do based on them
def process_argument(arg):
   
    if arg in ["-h", "--help", "help", "h"]:
        help()
        return False  # Makes the system continue to run
    
    elif arg in ["-p", "--passive", "passive", "p"]:
        print("Passive listening set")
        return False  
    
    elif arg in ["-e", "--exit", "exit", "e"]:
        print("Exiting the program")
        return True  # Exits the system
    
    else:
        print(f"Invalid option: {arg}. Please see options below") # F-String included to show variable arg. 
        help()
        return False  


def main():
    # Initially call the help function only if its the first time the process is ran
    global help_shown

    if help_shown == False:
        help()
        help_shown = True

        
  # Checks command-line arguments
    if len(sys.argv) > 1:    
        for arg in sys.argv[1:]: # Iterate through all args (to end of list)
            if process_argument(arg):
                return  

    # Interactive prompt if no arguments are provided / continuous loop until exit
    while True:
        user_input = input("Please select an option:  ").strip()       
        if process_argument(user_input): # Processes the user input as if it were a command-line argument
            break  



 

main()
