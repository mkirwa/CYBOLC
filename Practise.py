def StringManipulation():
    email = "mahlon.k.kirwa@army.mil"
    temp1 = email.replace('@',".")
    temp2 = temp1.replace('.',',')
    lst = temp2.split(",")
    print(lst)

def IfStatements():
    a = 5
    if a < 10 :
        print(f'{a} is less that 10')

    if a > 1:
        print(f'{a} is greater than 1')

    if a==5:
        print(f'{a} is equal to 5')

def playGame():
  while(True):
    action = input("Action? ")
    if action == 'help':
      print("N S E W help quit")
      continue
    elif action == 'quit':
      print('Thanks for playing')
      break
    elif action in ['N','S','E','W']:
      print(f'You moved {action}')
    elif action not in ['N','S','E','W']:
        print('That was not a valid option')
        pass


if __name__== "__main__":
    playGame()