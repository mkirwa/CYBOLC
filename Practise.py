import hashlib

def StringManipulation():
    email = "mahlon.k.kirwa@army.mil"
    temp1 = email.replace('@',".")
    temp2 = temp1.replace('.',',')
    lst = temp2.split(",")
    print(lst)


    temp = email.split('.')
    temp2 = '@'.join(temp)
    lst = temp2.split('@')

# def IfStatements():
#     a = 5
#     if a < 10 :
#         print(f'{a} is less that 10'import hashlib)
# import hashlib
#     if a > 1:
#         print(f'{a} is greater than 1')

#     if a==5:
#         print(f'{a} is equal to 5')

# # TODO: Function for class assignments
# def classAssignments():
#     pass

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


def replace_in_file_2(in_path, out_path, reps):
    temporary_values = dict(reps)
    with open(in_path, 'r') as newOne, open(out_path, 'w') as newOneTwo:
        for line in newOne:
            for find, replace in temporary_values.items():
                line = line.replace(find, replace)
            newOneTwo.write(line)


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


def replace_in_file_2(in_path, out_path, reps):
    temporary_values = dict(reps)
    print(temporary_values)
    with open(in_path, 'r') as newOne, open(out_path, 'w') as newOneTwo:
        for line in newOne:
            for find, replace in temporary_values.items():
                line = line.replace(find, replace)
            newOneTwo.write(line)


def get_hash(data="python"):
    '''
    Returns the SHA3 256-bit hash of the data provided.
    You will need to use the hashlib python library to complete this challenge.
       
    NOTE: The first call will use the string "python" later calls will use random strings
    NOTE: You can convert a string into a bytes-like object which is needed for hashing with: 
             
    data.encode("utf-8")
    
    NOTE: You can create a bytes-like object out of a literal by adding a b in front of the string, ie b"python" or b'python'
       
    Args:
        data (str): data to be encoded
    Returns:
        str : The SHA3 256-bit hash of the provided data
    '''    
    # Convert the data to bytes 
    temp1 = data.encode('utf-8')
    # Return the sha for the algorithm
    temp2 = hashlib.sha3_256(temp1)
    # Use hexdigest to get the 
    return temp2.hexdigest()




def findProduct(a,b):
    return a * b

def evensandodds(first, last):
    # Print out every even 
    name = range()
    pass



def get_type_str(obj):
    # if isinstance(obj,str):
    #     return str(type(obj))
    # elif isinstance(obj,bool):
    #     return str(type(obj))
    # elif isinstance(obj,int):
    #     return str(type(obj))
    # elif isinstance(obj,float):
    #     return str(type(obj))
    # elif isinstance(obj,list):
    #     return str(type(obj))
    # elif isinstance(obj,tuple):
    #     return str(type(obj))
    # else:
    #     return 'unknown'


    if obj == str:
        return "string"
    elif obj == bool:
        return "boolean"
    elif obj == int:
        return "integer"
    elif obj == float:
        return "float"
    elif obj == list:
        return "list"
    elif obj == tuple:
        return "tuple"
    else:
        return "unknown"
    
def sort_ascii(filepath):
    with open(filepath, 'r') as file:
        temp = []
        for line in file.readlines():
            temp.append(line.strip())
        sorted_temp = sorted(temp, key=lambda s: s.lower())
        return sorted_temp

def sort_length(filepath):
    with open(filepath, 'r') as file:
        temp = []
        for line in file.readlines():
            temp.append(line.strip())
        
    sorted_temp = sorted(temp, key=len, reverse=True)
    
    return sorted_temp

def sort_embedded(filepath):
    with open(filepath, 'r') as file:
        temp = []
        for line in file.readlines():
            temp.append(line.strip())

    def extract_embedded_number(line):
        return int(line[9:15]) 
    
    sorted_temp = sorted(temp, key=extract_embedded_number)
        
    return sorted_temp


def sort_embedded(filepath):
    
    with open(filepath,'r') as filepath:
        lines = filepath.readlines()
        lines = [line.strip() for line in lines]
        

    def sort_embedded_number(line):
        return int(line[10:16])
    
    line_new = lines.sort(lines, key=sort_embedded_number)
    
    return line_new

def round_to_position(lst):
    return [round(value, index) for index, value in enumerate(lst)]

# def replace_in_file(in_path, out_path, reps):
#     temporary_values = dict(reps)
#     with open(in_path, 'r') as newOne, open(out_path, 'w') as newOneTwo:
#         for line in newOne:
#             for find, replace in temporary_values.items():
#                 line = line.replace(find, replace)
#             newOneTwo.write(line)

def count_words(filepath):
    
    #with open(filepath, 'r') as new_file:
        #read_new_file = new_file.read()
    read_new_file = open(filepath, "r") 
    # Create an empty dictionary 
    d = dict() 

    # Loop through each line of the file 
    for line in read_new_file: 
        # Remove the leading spaces and newline character 
        line = line.strip() 

        # Split the line into words 
        words = line.split(" ") 

        # Iterate over each word in line 
        for word in words: 
            if word in d: 
                # Increment count of word by 1 
                d[word] = d[word] + 1
            else: 
                # Add the word to dictionary with count 1 
                d[word] = 1
    return d

# def numsys(startint):
#     pass

# def getints(binnum, octnum, decnum, hexnum):
#     pass
# def literals():
#     pass
    
import string
def complexity(password):
    correct_password = 0 
    if len(password) >=15:
        correct_password|= 0x1
    
    for char in password:
        if any(char.isdigit()):
            correct_password |= 0x2

    for char in password:
        if any(char.isupper()):
            correct_password |= 0x4
    
    for char in password:
        if any(char.islower()):
            correct_password |= 0x8

    for char in password:
        if any(char in string.punctuation):
            correct_password |= 0x10

    return correct_password


    correct_password = 0

    if len(password) >= 15:
        correct_password |= 0x1
    if any(char.isdigit() for char in password):
        correct_password |= 0x2
    if any(char.isupper() for char in password):
        correct_password |= 0x4
    if any(char.islower() for char in password):
        correct_password |= 0x8
    if any(char in string.punctuation for char in password):
        correct_password |= 0x10

    return correct_password

def q1_kjhk(floatstr):  
    list_conv = list(floatstr)
    return list(floatstr)
    return [float(value) for value in floatstr.split(",")]

def q1_another(*args):
    return int(sum(args))/len(args)

def q1_03(lst,n):
    return lst[-n:]

def q1_04(strng):
    list_ord = []
    for i in strng:
        list_ord.append(ord(i))
    return list_ord

def q1_05(strng):
    list_temp = []
    for value in strng.split(" "):
        list_temp.append(value)
    return tuple(list_temp)

def perms(mode):

    permissions = ['r', 'w', 'x']

    permissions_1 = (mode >> 6) & 0b111
    permissions_2 = (mode >> 3) & 0b111
    permissions_3 = mode & 0b111

    def converting_permission_bits_to_strings(permission_bits):
        perm_str = ''
        for idx, char in enumerate(permissions):
            perm_str += char if permission_bits & (1 << (2 - idx)) else '-'
        return perm_str

    
    permission_strings = converting_permission_bits_to_strings(permissions_1) + converting_permission_bits_to_strings(permissions_2) + converting_permission_bits_to_strings(permissions_3)
    
    return permission_strings

def q6(catalog, order):
    total = 0   
    for key, value in catalog.items():
        for i in order:
            if key==i[0]:
                print(f'value: {value} orders {i[1]}')
                total = total + (i[1]*value) 
    
    return total

def q1_new(filename):
    new_file_name = filename.readlines()
    return len(new_file_name.strip())

    #  first_line = file.readline()
        
    #     # Return the length of the line excluding the line terminator
    #     return len(first_line.strip())

    # with open(filename, 'r') as new_file:
    #     read_new_file = new_file.read()
    
    # return len(read_new_file.strip())



    # with open(filename, 'r') as new_file:
    #     read_new_file = new_file.read()
    
    # return len(read_new_file.strip())

def q1_08(filename,lst):
    with open(filename,'w') as new_file:
        for i in lst:
            if i!='stop':
                new_file.writelines(f'{i}\n')
            else:
                break
    
def q1_09(miltime):
    hour = int(miltime[:2])
    if 3 <= hour <= 11:
        return "Good Morning"
    elif 12 <= hour <= 15:
        return "Good Afternoon"
    elif 16 <= hour <= 20:
        return "Good Evening"
    else:
        return "Good Night"



        # for i in lst:
        #     if not 'stop':
        #         new_file.writelines(i)
        #         break



        # new_file_name = new_file.readline()
        # return len(new_file_name.strip())

if __name__== "__main__":
    in_path = 'qi_08.txt'
    lst = ['one','two','three','stop','four']
    q1_08(in_path,lst)
    # out_path = 'assignment3.txt'
    # reps = [("taken","delivered"),("cat","dog"),("outside","beyond"),("straightaway","forthwith"),("possibly","perchance")]
    # replace_in_file_2(in_path,out_path,reps)
    # user_input_1 = int(input("Enter a number 1: "))
    # user_input_2 = int(input("Enter a number 2: "))
    # print(findProduct(user_input_1,user_input_2))
    #print(get_hash())
    #q1_another(1,2,3,4)
    #count_words(in_path)
    #print(q1_03([1,2,3,4],3))
    #strng = "Long sentence to the test capabilities function's"
    #print(q1_05(strng))
    # catalog = {'AMD Ryzen 5 5600X': 289.99,\
    #            'Intel Core i9-9900K': 363.50,\
    #             'AMD Ryzen 9 5900X': 569.99}
    # order = [('AMD Ryzen 5 5600X', 5), \
    #          ('Intel Core i9-9900K', 3)]
    # print(q6(catalog,order))


