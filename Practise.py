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
    while Temp:
        action = input("Enter a value or a string to play a game: ")

        if action in ['N','S','E','W']:
            print(f'You moved to {action}')
            continue
        elif action not in ['N','S','E','W','help','quit']:
            print(f'{action} is an invalid option')
        elif action == 'quit':
            print("Thanks for playing")
            Temp = False
        elif action == 'help':
            print('N S E W help quit')

def leetString(s):
    emptyList = []
    lists = list(s)

    for i in range(0,len(lists)):
        if(i%2==0):
            emptyList.append(lists[i].upper())
        if(i%2!=0):
            emptyList.append(lists[i].lower())
    newword = ''.join(emptyList)
    return newword

def reverse_string(strng):
    '''
    Returns a copy of the given string reversed
    Args:
        strng (str): a string of alphanumeric characters
    Returns:
        str: a copy of the given string reversed
    '''    
    return strng[::-1]

def make_tuples():
    '''
     Returns a tuple of the multiples of 10 from 1 to 100 inclusive.
     Args:
         None
     Returns:
         tuple: a tuple of the multiples of 10 from 1 to 100 inclusive
     '''
    pass

def make_tuple(a,b):
    listTuple = []
    for i in range(a,b+1):
        if i%10==0:
            listTuple.append(i)
    return tuple(listTuple)

def disect(lst):
    numberLength = len(lst)
    halve = numberLength/2
    print(halve)
    tuple1 = lst[0:int(halve)]
    tuple2 = lst[int(halve):numberLength]

    finalList = tuple([tuple1,tuple2])
    print(finalList)

def tough_read(fname):
    """ Args: fname (str): path to a file where the input is located Returns: str: Sentence that was decoded """
    integers = []
    with open(fname, 'r') as f:
        binary_string = f.readlines()


    for b in binary_string:
        integers.append(chr(int(b,base=2)))

    # Convert the list of integers to a Unicode string
    unicode_string = ''.join(integers)
    
    return unicode_string

def log_to_file(fname, theme):
    '''
    Args:
        fname (str): Path to an existing file that includes previous inspirational messages to keep.
        theme (str): Theme to be placed on each line.
    Returns:
        None
    '''
    # Open the file in 'append' mode
    with open(fname, 'a') as file:
        while True:
            user_input = input("Enter an inspirational message (or leave it empty to finish): ")
            if not user_input:
                break  # Exit the loop if the input is empty
            formatted_message = f'{theme}:{user_input}\n'  # Format the message
            file.write(formatted_message)  # Write the message to the file



def replace_in_file(in_path, out_path, reps):
    # Read the input file and create a dictionary from the replacements
    temporary_values = dict(reps)

    # Open the input file for reading and the output file for writing
    with open(in_path, 'r') as newOne, open(out_path, 'w') as newOneTwo:
        # Iterate through each line in the input file
        for line in newOne:
            # Replace occurrences of words in the line using the dictionary
            for find, replace in temporary_values.items():
                line = line.replace(find, replace)
            # Write the modified line to the output file
            newOneTwo.write(line)

if __name__== "__main__":
    fname = 'assignment2.txt'
    theme = 'Razzman'
    print(tough_read(fname,theme))