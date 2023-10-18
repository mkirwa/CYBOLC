def StringManipulation():
    email = "mahlon.k.kirwa@army.mil"
    temp1 = email.replace('@',".")
    temp2 = temp1.replace('.',',')
    lst = temp2.split(",")
    print(lst)


    temp = email.split('.')
    temp2 = '@'.join(temp)
    lst = temp2.split('@')

def IfStatements():
    a = 5
    if a < 10 :
        print(f'{a} is less that 10')

    if a > 1:
        print(f'{a} is greater than 1')

    if a==5:
        print(f'{a} is equal to 5')

# TODO: Function for class assignments
def classAssignments():
    pass

def playGame():
    Temp = True 
    while Temp == True:
        action = input("Enter a value or a string to play a game: ")
        if action == 'quit':
            print("Thanks for playing")
            Temp = False
        elif action == 'help':
            print('N S E W help quit')
        elif action in ['N','S','E','W']:
            print(f'You moved to {action}')
        elif action not in ['N','S','E','W']:
            print(f'{action} is an invalid option')


if __name__== "__main__":
    playGame()