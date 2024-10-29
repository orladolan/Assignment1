
# Variables
help_shown = False     # Variable to track if help has been shown


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



def main():
   
   # Call the help function only if its the first time the process is ran
    global help_shown

    if help_shown == False:
        help()
        help_shown = True

   # Takes the user's input 
    userInput = input("""
    Please select an option: """).strip().lower() # To accept all inputs in a universal format

   # Handling the input
    while userInput != "exit":
        if userInput == "help" or userInput == "h":
            help()
        elif userInput == "passive" or userInput == "p":
            print("""
    Passive listening set""") 
        else: 
            print("""
    Invalid option. Type 'help' for more information""")
  
   
        # Ask for the next option or to exit
        userInput = input("""
    Please select another option or type 'exit' to quit: """).strip().lower()

main()
