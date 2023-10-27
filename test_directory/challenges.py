''' 
Day 3: Iterables/Slicing/File(I/O)
Day 4: Libraries/name==main /sorting
Day 5: Sets, Dictionaries/Args:kwargs
Day 6: Binary
Day 7: Classes
Day 8: Error Handling /Review
Day 9: Review/Practises 
Day 10: Exam

'''


'''

************************ 01 ***************************************
Use python to produce code below that will create several named variables with the specified value:

Variable	        Value	Type
hello	            hello	string
is_python_awesome	true	boolean
days_in_python	    6	    integer
pie_size	        3.14	float

NOTE: Do not indent your code '''

############################# SOLUTION ##############################

hello = 'hello'
is_python_awesome = True
days_in_python = 6
pie_size = 3.14


'''

************************ 02 ***************************************

Use Python to produce code below that will convert the provided literal ("Starting Value"), convert it to the indicated data type by using the appropriate Python Built-in Function(s), and assign the output to the named variable as designated below.

Task	            Variable	    Starting Value	    Convert to Type
string to int	    int_input	    "345"	            int
string to float	    pi_4	        "3.1415"	        float
int to string	    hours_str	    40	                string
int to float	    hourly_rate	    15	                float
NOTE: Conversion functions must be called
NOTE: Do not indent your code

'''

############################# SOLUTION ##############################

int_input = int("345")
pi_4 = float("3.1415")
hours_str = str(40)
hourly_rate = float(15)

'''
************************ 03 ***************************************

Use python to produce code below that will create several named variables with the specified value using math operators:

Variable	Value	                    Type
x	        16	                        integer
y	        3	                        integer
xysum	    sum of x and y	            integer
xydiff	    difference of x and y	    integer
xyprod	    product of x and y	        integer
xyquo	    quotient of x and y	        float
xyintquo	integer quotient of x and y	integer
xymod	    modulus of x and y	        integer
NOTE: Do not indent your code

'''

############################# SOLUTION ##############################

x = 16
y = 3
xysum = x + y
xydiff = x - y 
xyprod = x * y 
xyquo = x / y 
xyintquo = x // y 
xymod = x % y

'''
************************ 04 ***************************************

Use python to produce code below that will create several named variables with the specified value using the str.format member function. You may assign any value for the variables other than output. The output variable must use the same boilerplate text and include the appropriate values assigned to the first three.

Identifier	Example Value	                                            Type
name	    Jerry	                                                    str
greeting	Sir	                                                        str
time	    noon	                                                    str
output	    Hello Jerry! Sir, will you be arriving by noon?	            str
NOTE: Do not indent your code

'''

############################# SOLUTION ##############################

name='Jerry'
greeting='Sir'
time='noon'
output = f'Hello {name}! {greeting}, will you be arriving by {time}?'

'''

************************ 05 ***************************************

Use python to produce code below that will perform the following:

    Create a variable named sentence and assign the value 'good for all'
    Turn the sentence variable into a list of individual characters and assign this to a variable named sent_list.
    Change the first (index 0) character in the list to 'f'
    Change the last (index -1) character in the list to '?'
    Combine the list into a new string with periods ('.') in between each character and assign the result to a new variable named output.

NOTE: Do not indent your code

'''

############################# SOLUTION ##############################

sentence = 'good for all'
sent_list = list(sentence)
sent_list[0] = 'f'
sent_list[-1] = '?'
output = str('.'.join(sent_list))

'''

************************ 06 ***************************************
#Read multiple numbers separated by spaces on the same line from the user.
#Change all spaces to a plus sign.
#Print the resulting string to the user.


#Read multiple numbers separated by spaces on the same line from the user.
#Change all spaces to a plus sign.
#Print the resulting string to the user.

'''

############################# SOLUTION ##############################

numbers = input()
numbers = numbers.replace(' ','+')
print(numbers)

'''

************************ 07 ***************************************

Use python to produce code below that will perform the following:

    Read input from the user, the input will be an integer.
    Determine which of the following categories the number fits into an print this to the user:
        Negative Even
        Negative Odd
        Zero
        Positive Even
        Positive Odd

'''

############################# SOLUTION ##############################
    
num = int(input())
if num%2==0 and num<0:
    print("Negative Even")
elif num%2==0 and num>0: 
    print("Positive Even")
elif num==0: 
    print("Zero")
elif num%2!=0 and num>0: 
    print("Positive Odd")
elif num%2!=0 and num<0: 
    print("Negative Odd")

'''

************************ 00 ***************************************

Use python to produce code below that will:

    Given an email address in email
    Convert the email into a list named `lst'
    The list will contain all individual parts of the email
    Example: email = 'alan.m.turing@genius.com' -> lst = ['alan','m','turing', 'genius', 'com']
    NOTE: A variable named email will be available to your code when running.
    NOTE: You must create a variable named lst which contains the required data.
    NOTE: Do not indent your code

'''
    
############################# SOLUTION ##############################
email = 'mahlonkibiwott@gmail.com'
temp = email.split('.')
temp2 = '@'.join(temp)
lst = temp2.split('@')

'''

************************ 00A ***************************************

FizzBuzz is an interview question that is said to filter out 99.5% of programming job candidates.

Add code so that it takes a number from the user and prints it (the number) if it isn’t divisible by 3 or 5. For multiples of 3 print 'fizz' instead. For multiples of 5 print 'buzz' instead. For multiples of 3 and 5 print 'fizzbuzz'.

'''
############################# SOLUTION ##############################

num = int(input())
if (num%3==0 and num%5==0):
    print('fizzbuzz')
elif(num%3==0):
    print('fizz')
elif (num%5==0):
    print('buzz')
else:
    print(num)

'''
************************ 08 ***************************************

Use python to produce code below that will perform the following:

    Read multiple numbers separated by spaces on the same line from the user.
    Change all spaces to a plus sign.
    Print the resulting string to the user.
NOTE: Do not indent your code

'''

############################# SOLUTION ##############################

numbers = input()
numbers = numbers.replace(' ','+')
print(numbers)


'''

************************ 08 ***************************************
Use python to produce code below that will perform the following:
    Create a function named domath that will accept 3 parameters.
    The function will add the first two parameters and multiply this sum by the third parameter.
    You can select the identifiers for each of the parameters.
The resulting product will be returned to the caller.

'''

############################# SOLUTION ##############################


def domath(param1,param2,param3):
    sum = (param1+param2)*param3
    return sum
'''

************************ 09 ***************************************


Use python to produce code below that will perform the following:

Read multiple lines from the user on standard input until an empty string is read.
Return a list of all these lines without line terminators
Each line should be reversed from how it is read in.
def reverseit():
    pass 
    
'''

############################# SOLUTION ##############################

def reverseit():
    word2 = []
    word4 = []
    while True:
        word = input()
        if not word:
            break
        for i in range(len(word)):
            word2.append(word[-i-1])
        word3 = ''.join(word2)
        print(word3)
        word4.append(word3)

        word2.clear()
        
    return word4
'''
************************ OOB ***************************************

Modify code below and implement guess_number so that it repeatedly asks the user for a number between 0 and 100, inclusive. If the user correctly guesses the value of the given argument n, print 'WIN' and return. Otherwise, indicate whether the guess was too high or too low.

def guess_number(n):
    pass

guess_number(23)
'''
############################# SOLUTION ##############################

def guess_number(n):

    temp = True
    while temp:
        num = int(input())
        if num==n:
            print('WIN')
            temp = False
        elif num>n:
            print('too high')
        elif num<n:
            print('too low')

guess_number(23)

'''

************************ 10 ***************************************

Use python to produce code below that will perform the following:

Given a mixed case string as parameter s
Capitalize every letter with an even index within the string.
Lowercase every letter with an odd index within the string.
Return the resulting string.
Example - Given: "ABCDEF ghijkl" Return: "AbCdEf gHiJkL"
def leetString(s):
    pass

'''

############################# SOLUTION ##############################

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
'''

************************ 11 ***************************************

Use python to produce code that will perform the following:

First, print out every even number on a separate line from provided parameter first to parameter last, inclusive.
Next, print out every odd number from first to last, inclusive.
def evensandodds(first, last):
   pass 

'''
############################# SOLUTION ##############################

def evensandodds(first, last):
    for i in range(first, last + 1):
        if i % 2 == 0:
            print(i)

    
    for i in range(first, last + 1):
        if i % 2 != 0:
            print(i)
'''

************************ 12 ***************************************

def user_io():

    Returns a list of items read from the user until the user enters an empty string.

    Args:
        None
    Returns:
        list: a list of strings
    pass
'''
############################# SOLUTION ##############################

def user_io():
    '''
    Returns a list of items read from the user until the user enters an empty string.

    Args:
        None
    Returns:
        list: a list of strings
    '''  
    word2 = []
    while True:
        word = list(input())
        if not word:
            break
        word2.append(''.join(word))
    return word2
'''

************************ 13 ***************************************

def make_tuple():
     Returns a tuple of the multiples of 10 from 1 to 100 inclusive.
     Args:
         None
     Returns:
         tuple: a tuple of the multiples of 10 from 1 to 100 inclusive
     pass    
'''
############################# SOLUTION ##############################

def make_tuple():
    return tuple(range(10,101,10))

'''

************************ 13-1- ***************************************

def make_tuple(a,b):
    
    Returns a tuple of the multiples of 10 from a to b inclusive.
    Args:
        None
    Returns:
        tuple: a tuple of the multiples of 10 from a to b inclusive
          
'''
############################# SOLUTION ##############################

def make_tuple(a,b):
    listTuple = []
    for i in range(a,b+1):
        if i%10==0:
            listTuple.append(i)
    return tuple(listTuple)

'''

************************ 14 ***************************************

def strings():
    
    Returns a tuple of the following two strings:

    

    Physics is the universe's operating system

    Args:
        None
    Returns:
        tuple: a tuple of strings
     
    pass   
    
'''
############################# SOLUTION ##############################

def strings():
    word = ('',"Physics is the universe's operating system")
    return word

'''

************************ 15 ***************************************

def disect(lst):
    
    Returns a tuple of the given list split into two equally sized halves.
    The given list will always consist of an even number of elements.
    Args:
        lst (lst): a list of elements
    Returns:
        tuple: a tuple of two lists
    
    pass     
'''
############################# SOLUTION ##############################

def disect(lst):
    numberLength = len(lst)
    halve = numberLength/2
    print(halve)
    tuple1 = lst[0:int(halve)]
    tuple2 = lst[int(halve):numberLength]

    finalList = tuple([tuple1,tuple2])
    return finalList

'''

************************ 16 ***************************************

def reverse_string(strng):
    
    Returns a copy of the given string reversed
    Args:
        strng (str): a string of alphanumeric characters
    Returns:
        str: a copy of the given string reversed
        
    pass   
    
'''
############################# SOLUTION ##############################

def reverse_string(strng):
    '''
    Returns a copy of the given string reversed
    Args:
        strng (str): a string of alphanumeric characters
    Returns:
        str: a copy of the given string reversed
    '''    
    return strng[::-1]

'''

************************ 17 ***************************************

Return a list of ordinals for every character in the given string

Hint: https://docs.python.org/3/library/functions.html#ord
def code_points(strng):
   pass   

'''

############################# SOLUTION ##############################

def code_points(strng):
    listtemp_points = []
    tempcode_points = list(strng)
    for i in tempcode_points:
        listtemp_points.append(ord(i))

    return listtemp_points

'''

************************ 18 ***************************************

Use python to produce code below that will perform the following:

Read file specified by the path in inpath parameter and write all lines to the file specified by the outpath parameter.
Before writing out each line, add the line number starting with 1 follow by colon and space.
def linenums(inpath, outpath):
    pass 

'''
############################# SOLUTION ##############################


def linenums(inpath, outpath):
    with open(inpath, 'r') as inpath_file:
        inpath_file_outpt = inpath_file.readlines()

    with open(outpath, 'w') as outfile:
        for index, line in enumerate(inpath_file_outpt, start=1):
            outfile.write(f"{index}: {line}")

'''

************************ 10 ***************************************
Use python to produce code below that will perform the following:

Read multiple lines from the user on standard input until an empty string is read.
Return a list of all these lines without line terminators
Each line should be reversed from how it is read in.

'''

############################# SOLUTION ##############################


def domath(param1,param2,param3):
    sum = (param1+param2)*param3
    return sum

'''

************************ 18-1 ***************************************
"Sometimes my cousin is just mean. He sent me a file with a special message but made it into a crazy series of ones and zeros. He told me each letter was on its own line, and could be converted into an Unicode character. Can you help me by decoding his message?"

Each line will be a string character. You will need to convert the string Ones and Zeros into an integer (but these are not base 10, so keep that in mind) and then pass that data to code that will convert it to its corresponding Unicode character. Thanks to Python's "batteries included" philosophy, there are two Python built-in functions that can help handle this for you.

Hint: https://docs.python.org/3/library/functions.html#int
Hint: https://docs.python.org/3/library/functions.html#chr
def tough_read(fname):
    
    Args:
        fname (str): path to a file where the input is located
    Returns:
        str: Sentence that was decoded
    
    pass 
NOTE: If you wish to create a file in the format that fname is in, the following code can create the file from a Bash Shell. This command will place the file in the directory of wherever this command is ran, and you will have to assign fname to the file name (either absolute or relative paths) in order to verify your code on your local system.


python3 -c "with open('act18_1.txt','w') as fp: fp.writelines(['{:08b}\n'.format(ord(c)) for c in 'Be all that you can be']); fp.  close()"

'''

############################# SOLUTION ##############################

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

'''

************************ 18-2 ***************************************

"You have a artist friend that likes to jot down some inspirational words when the mood strikes. These fits of inspiration always have a theme that they need to remember with the messages. Your friend needs some help keeping track. Read each of the inspirational messages from the user and write them to the end of the file specified by fname. Since the theme is important and must be remembered, add the theme and a colon before each message and ensure each inspirational message is on its own line. An empty input will indicate no more entries and the end of the theme."

Example:

If theme was "Razzmatazz", and the input from the user was "I like nonsense; it wakes up the brain cells. - Dr. Seuss", the resulting string would be formated as follows: Razzmatazz:I like nonsense; it wakes up the brain cells. - Dr. Seuss

Important:

What if there are other lines to be added? What else seperates lines in a file? What needs to be added to the example line above?
Do not overwrite the file. What mode should you open the file in?
def log_to_file(fname, theme):
    
    Args:
        fname (str): Path to an existing file that includes previous inspirational messages to keep.
        theme (str): Theme to be placed on each line.
    Returns:
        None
    
    pass 
    
'''

############################# SOLUTION ##############################

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


#with open('new.txt','w') as new:
    #lines = ['line 1\n','line 2\n','line 3\n']
    #new.writelines(lines)

'''

************************ 18-3 ***************************************

Replace all found instances of the individual tuple entries in the file found at in_path. Replacements will be in the list reps as a list of tuples. Each tuple entry will contain the 'find' as the first element and the 'replace' will be the second element. Write the result to the file specified with out_path.

Example:

List of Tuples example - [("taken","delivered"),("cat","dog"),("outside","beyond"),("straightaway","forthwith"),("possibly","perchance")]
Original string example - "The cat possibly needs to be taken outside, straightaway."
Changed string example - "The dog perchance needs to be delivered beyond, forthwith."
def replace_in_file(in_path, out_path, reps):
    
    Args:
        in_path (str): input file path
        out_path (str): output file path
        reps (list): list of tuples containing ("find", "replace") mappings
    Returns:
        None
    
    pass 
    
'''

############################# SOLUTION ##############################

def replace_in_file(in_path, out_path, reps):
    temporary_values = dict(reps)
    with open(in_path, 'r') as newOne, open(out_path, 'w') as newOneTwo:
        for line in newOne:
            for find, replace in temporary_values.items():
                line = line.replace(find, replace)
            newOneTwo.write(line)

'''

************************ 19 ***************************************

def grab(lst):
    
    Returns a randomly chosen item from the given list (lst).
    Args:
        lst (list): a list of items
    Returns:
        item (?): an item from the list
    
'''

############################# SOLUTION ##############################

import random
def grab(lst):
    '''
    Returns a randomly chosen item from the given list (lst).
    Args:
        lst (list): a list of items
    Returns:
        item (?): an item from the list
    '''    
    return random.choice(lst)

'''

************************ 20 ***************************************

def get_hash(data="python"):
    
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

############################# SOLUTION ##############################

import hashlib

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
    temp1 = data.encode('utf-8')
    temp2 = hashlib.sha3_256(temp1)
    return temp2.hexdigest()

'''

************************ 21 ***************************************

Write a script that implements a function, find_product, which takes two numbers and 
returns the product. Use the name=='__main__' idiom to prompt the user for two integers a 
print the result of calling find_product using those integers.

'''
############################# SOLUTION ##############################

def find_product(a,b):
    return a * b
if __name__== "__main__":
    user_input_1 = int(input())
    user_input_2 = int(input())
    print(find_product(user_input_1,user_input_2))

'''

************************ 22 ***************************************

Write a function, round_to_position, which takes a list of floats and returns a new list with the original floats each rounded to the number of digits of precision after the decimal point corresponding to the original float's position in the list.

def round_to_position(lst):
    pass

    '''
############################# SOLUTION ##############################

def round_to_position(lst):
    return [round(value, index) for index, value in enumerate(lst)]

'''

************************ 23 ***************************************

def get_type_str(obj):
    
    Returns the type of the parameter as a string.
    Possible types are:  
string  
boolean   
integer  
float   
list  
tuple

    NOTE: Any other types should be identified with 'unknown'
    Args:
        obj (?): The object that should be classified
    Returns:
        str : The type of the provided data
       
'''
############################# SOLUTION ##############################

def get_type_str(obj):
    obj = type(obj)
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
        return str("unknown")
'''

************************ 24 ***************************************

Use python to produce code below that will perform the following:

The file specified by fname contains some text.
A list of words is provided as the parameter words.
Return a list of all the words found in the file that are NOT contained in the list of words in parameter.
Each word in the file will be separated by at least one character of whitespace.
def diffwords(fname, words):
    pass 

'''

############################# SOLUTION ##############################

def diffwords(fname, words):
    with open(fname, 'r') as filein:
        text = set(filein.read().split())
        diff = text.difference(words)
    
    return diff
'''

************************ 25 ***************************************
def count_words(filepath):
    
    Count the occurrences of each word in the file. Create a dictionary that contains each word in the file as a key
    and the value for each key will contain the number of times each words is found in the file. Words will be
    separated by one or more whitespace characters spread over multiple lines.
       
    Args:
        filepath (str): The path to the file
    Returns:
        dict : keys - words
               values - number of times each word appears

'''

############################# SOLUTION ##############################

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
            print(word)
            # Check if the word is already in dictionary 
            # crayons['orange'] = 'mango' 
            if word in d: 
                # Increment count of word by 1 
                d[word] = d[word] + 1
            else: 
                # Add the word to dictionary with count 1 
                d[word] = 1

    return d

'''

************************ 26 ***************************************

Use python to produce code below that will perform the following:

    Create a function called infinitearguments that will:
    Print to standard output all positional arguments, in the order received, on separate lines.
    Followed immediately by all keyword arguments in the form keyword=value in keyword alphabetic order.

'''
############################# SOLUTION ##############################

def infinitearguments(*args, **kwargs):
    for arg in args:
        print(arg)
    
    myKeys = list(kwargs.keys())
    myKeys.sort()
    sorted_dict = {i: kwargs[i] for i in myKeys}
    
    for key, value in sorted_dict.items():
        print(f'{key}={value}')

'''

************************ 27 ***************************************

def sort_ascii(filepath):
    
    Read all lines from file in `filepath` and return a list of all lines in case-insensitive ASCII order.
    Remove all linebreaks before sorting.
       
    Args:
        filepath (str): The path to the file
    Returns:
        list : lines from input file sorted into ASCII order without linebreaks
    
'''

############################# SOLUTION ##############################

def sort_ascii(filepath):
    with open(filepath, 'r') as file:
        temp = []
        for line in file.readlines():
            temp.append(line.strip())
        sorted_temp = sorted(temp, key=lambda s: s.lower())
        return sorted_temp

'''

************************ 28 ***************************************

def sort_length(filepath):
    
    Read all lines from file in `filepath` and return a list of all lines sorted longest to shortest.
    Remove all linebreaks before sorting.
       
    Args:
        filepath (str): The path to the file
    Returns:
        list : lines from input file sorted longest to shortest without linebreaks

'''

############################# SOLUTION ##############################

def sort_length(filepath):
    with open(filepath, 'r') as file:
        temp = []
        for line in file.readlines():
            temp.append(line.strip())
        
    sorted_temp = sorted(temp, key=len, reverse=True)
    
    return sorted_temp

'''

************************ 29 ***************************************

def sort_embedded(filepath):
    
    Read all lines from file in `filepath` and return a list of all lines sorted numerically by
    the number at character positions 10 to 15 in each line..
    Remove all linebreaks before sorting.
    
    Example: The embedded number is 561234 below. Copy and paste this into a text file to test your function:
		
    Here is a561234 long line of text from the file.
       
    Args:
        filepath (str): The path to the file
    Returns:
        list : lines from input file numerically sorted on the embedded number without linebreaks

'''


############################# SOLUTION ##############################

def sort_embedded(filepath):
    with open(filepath, 'r') as file:
        temp = []
        for line in file.readlines():
            temp.append(line.strip())
    def extract_embedded_number(line):
        return int(line[9:15]) 
    
    sorted_temp = sorted(temp, key=extract_embedded_number)
        
    return sorted_temp

'''

************************ 120 ***************************************

def numsys(startint):
    """ Given an integer `startint`, convert this integer to its 
    binary version, octal version, and hexadecimal version and 
    return these as a tuple in the order given. """
    pass
    
def getints(binnum, octnum, decnum, hexnum):
    """ Given the string parameters `binnum` (binary number), 
    `octnum` (octal number), decnum` (decimal number), `hexnum` 
    (hexadecimal number), convert each of these  to an integer and 
    return them as a list in their parameter order. """
    pass
    
def literals():
    """ Create a list and set the value using literals and return 
    the list. All literals will represent the decimal integer value 
    1,000,000 (one million). You must use a literal to represent 
    the target value in binary, hexadecimal, decimal, and octal.
    The order is not important. """
    pass
    
'''
############################# SOLUTION ##############################


def numsys(startint):
    binary_num = bin(startint)
    octal_num = oct(startint)
    hex_num = hex(startint)
    return (binary_num, octal_num, hex_num)

def getints(binnum, octnum, decnum, hexnum):
    integer_binary = int(binnum, 2)
    integer_octa_number = int(octnum, 8)
    integer_decimal = int(decnum)
    hex_number = int(hexnum, 16)
    
    return [integer_binary, integer_octa_number,integer_decimal, hex_number]

def literals():
    binary_literal = 0b11110100001001000000
    hexadecimal_literal = 0xf4240
    decimal_literal = 1000000
    octa_literal = 0o3641100
    return [binary_literal, hexadecimal_literal, decimal_literal, octa_literal]

'''

************************ 120 ***************************************

Given a password as a string, return an integer whose bits are set according to the following rules:

0x1 - Consists of at least 15 characters
0x2 - Consists of at least 1 number
0x4 - Consists of at least 1 uppercase letter
0x8 - Consists of at least 1 lowercase letter
0x10 - Consists of at least 1 special character (~!"@#$%^&'*_-+=`|(){}[]:;<>,.?/)
Note: The set of special characters corresponds exactly with those characters in string.punctuation

def complexity(password):
    pass

'''
############################# SOLUTION ##############################


import string
def complexity(password):
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

'''

************************ 101 ***************************************

Given a linux file mode (permissions) as an integer, return the permission string that the mode represents.

Example 1:
mode = 511 
511 == 0b111111111
permissons = 'rwxrwxrwx'

Example 2:
mode = 424
424 == 0b110101000
permissions = 'rw-r-x---'
def perms(mode):
    pass

'''
############################# SOLUTION ##############################

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

    def get_perm_str(perms_bits):
        return ''.join(PERMISSIONS.get(bit, '-') for bit in [4, 2, 1] if bit & perms_bits)

    perm_str = get_perm_str(user_perms) + get_perm_str(group_perms) + get_perm_str(other_perms)

    return perm_str

'''

************************ 01 ***************************************

Given the floatstr, which is a comma separated string of floats, return a list with each of the floats in the argument as elements in the list.

def q1(floatstr):  
    pass
    
'''
############################# SOLUTION ##############################

def q1(floatstr):  
    return [float(value) for value in floatstr.split(",")]

'''
************************ 02 ***************************************

Given the variable length argument list, return the average of all the arguments as a float

def q1(*args):
    pass

'''
############################# SOLUTION ##############################

def q1(*args):
    return int(sum(args))/len(args)

'''

************************ 03 ***************************************

Given a list (lst) and a number of items (n), return a new list containing the last n entries in lst.


def q1(lst,n):
    pass
    
'''
############################# SOLUTION ##############################

def q1(lst,n):
    return lst[-n:]

'''

************************ 04 ***************************************

Given an input string, return a list containing the ordinal numbers of each character in the string in the order found in the input string.

def q1(strng):
    pass

'''

############################# SOLUTION ##############################

def q1(strng):
    list_ord = []
    for i in strng:
        list_ord.append(ord(i))
    return list_ord

'''

************************ 05 ***************************************

Given an input string, return a tuple with each element in the tuple containing a single word from the input string in order.

def q1(strng):
    pass

'''

############################# SOLUTION ##############################

def q1(strng):
    list_temp = []
    for value in strng.split(" "):
        list_temp.append(value)
    #list_temp_new = sorted(list_temp)
    return tuple(list_temp)

'''

************************ 06 ***************************************

Given a dictionary (catalog) whose keys are product names and values are product prices per unit and a list of tuples (order) of product names and quantities, compute and return the total value of the order.

Example catalog:

{
'AMD Ryzen 5 5600X': 289.99,
'Intel Core i9-9900K': 363.50,
'AMD Ryzen 9 5900X': 569.99
}
Example order:

[
('AMD Ryzen 5 5600X', 5), 
('Intel Core i9-9900K', 3)
]
Example result:

2540.45

How the above result was computed:

(289.99 * 5) + (363.50 * 3)

def q6(catalog, order):
    pass

'''
############################# SOLUTION ##############################


def q6(catalog, order):
    total = 0   
    for key, value in catalog.items():
        for i in order:
            if key==i[0]:
                print(f'value: {value} orders {i[1]}')
                total = total + (i[1]*value) 
    
    return total

'''

************************ 07 ***************************************

coding python
Given a filename, open the file and return the length of the first line in the file excluding the line terminator.

def q1(filename):
    pass

'''

############################# SOLUTION ##############################

def q1(filename):
    with open(filename,'r') as new_file:
        new_file_name = new_file.readline()
        return len(new_file_name.strip())

'''

************************ 08 ***************************************

Given a filename and a list, write each entry from the list to the file on separate lines until a case-insensitive entry of "stop" is found in the list. If "stop" is not found in the list, write the entire list to the file on separate lines.

def q1(filename,lst):
    pass
    
'''

############################# SOLUTION ##############################

def q1(filename,lst):
    with open(filename,'w') as new_file:
        for i in lst:
            if i!='stop':
                new_file.writelines(i)
                new_file.writelines('\n')
            else:
                break

'''
************************ 09 ***************************************

Given the military time in the argument miltime, return a string containing the greeting of the day.

0300-1159 "Good Morning"
1200-1559 "Good Afternoon"
1600-2059 "Good Evening"
2100-0259 "Good Night"
def q1(miltime):
    pass

'''
############################# SOLUTION ##############################

def q1(miltime):
    hour_str = str(miltime).zfill(4)  
    hour = int(hour_str[:2])
    
    if 3 <= hour <= 11:
        return "Good Morning"
    elif 12 <= hour <= 15:
        return "Good Afternoon"
    elif 16 <= hour <= 20:
        return "Good Evening"
    else:
        return "Good Night"

'''

************************ 10 ***************************************

Given the argument numlist as a list of numbers, return True if all numbers in the list are NOT negative. If any numbers in the list are negative, return False.

def q1(numlist):
    pass
    
'''

############################# SOLUTION ##############################

def q1(numlist):
    for i in numlist:
        if int(i)<0:
            return False
        else:
            return True

'''
************************ 105 ***************************************

Implement a class named Calculator

__init__ should not take additional arguments and should be used to initialize the internal state.
Provide add, sub, mul, and div member functions and each accepts two operands
The last result must be available for the next operation.
A single memory value must also be available.
Provide a store function to store the current last result to memory
Provide a recall function to recall the current memory value into the last result
Each member function can use the following as values to each math operation:
A number for a normal operation
An empty string '' to denote the last result
'memory' to denote the memory location
Each member function must return the numeric result of the operation
String conversion of a Calculator instance should be the last result as a string
All values provided will be valid and should be handled.
#!/usr/bin/env python3

class Calculator:
    
    def __init__(self):
        pass

'''

############################# SOLUTION ##############################

#!/usr/bin/env python3

class Calculator:
    def __init__(self):
        self.result = 0
        self.memory = 0

    def add(self,param1, param2):
        total = self.inputvalue(param1) + self.inputvalue(param2)
        self.result = total
        return total
    
    def sub(self,param1, param2):
        total = self.inputvalue(param1) - self.inputvalue(param2)
        self.result = total
        return total

    def mul(self,param1, param2):
        total = self.inputvalue(param1) * self.inputvalue(param2)
        self.result = total
        return total

    def div(self,param1, param2):
        total = self.inputvalue(param1) / self.inputvalue(param2)
        self.result = total
        return total
    
    def recall(self):
        self.result = self.memory
        return self.result
    
    def store(self):
        self.memory = self.result
    
    def __str__(self):
        return str(self.result)
    
    def inputvalue(self, value):
        if value == '':
            return self.result
        elif value == 'memory':
            return self.memory
        else:
            return value

'''

************************ 102 ***************************************

Given a username as a string, crack the user's 4 digit pin by repeatedly calling the provided login function. Incorrect attempts to login will raise PermissionError so this, and only this, exception must be caught. Return the pin used to successfully log in.

login(username,pin)
   
Returns True if the username and pin are correct. Otherwise raises PermissionError.
def crack(username):
    pass
    
'''
############################# SOLUTION ##############################
def login():
    pass

def crack(username):
    for i in range(10000):
        pin = f"{i:04d}"
        try:
            if login(username, pin):
                return pin
        except PermissionError:
            continue
    return None

'''

************************ 10 ***************************************

Attempt to convert the string 'abc' into an integer

Capture the error and print Error has been detected

Then attempt to convert the string '123' into an integer

When no errors are detected print No errors detected

Include a statement that prints operations are complete whether errors are detected or not

'''

############################# SOLUTION ##############################

try:
    new_string = int('abc')
except ValueError:
    print('Error has been detected')
try: 
    new_integer = int('123')
except ValueError:
    print('Error has been detected')
else:
    print('No errors detected')
finally:
    print('operations are complete')

'''

************************ 02 ***************************************

Given a positive integer, return its string representation with commas seperating groups of 3 digits.

For example, given 65535 the returned string should be '65,535'.

def q1(n):
    pass
    
'''

############################# SOLUTION ##############################

def q1(n):
    return '{:,}'.format(n)

'''

************************ 02 ***************************************

Given two lists of integers, return a sorted list that contains all integers from both lists in descending order.

For example, given [3,4,9] and [8,1,5] the returned list should be [9,8,5,4,3,1]. The returned list may contain duplicates.

def q1(lst0, lst1):
    pass

'''

############################# SOLUTION ##############################

def q1(lst0, lst1):
    #list_1 = list(lst0)
    new_list = lst0 + lst1
    #list_2 = list(lst1)
    #list_2.sort()
    new_list.sort(reverse=True)
    return new_list

'''

************************ 04 Pass GO and collect $200
 ***************************************

Given 3 scores in the range [0-100] inclusive, return 'GO' if the average score is greater than 50. Otherwise return 'NOGO'.

def q1(s1,s2,s3):
    pass
'''
############################# SOLUTION ##############################

def q1(s1,s2,s3):
    if (s1>=0 and s1<=100) and (s2>=0 and s2<=100) and (s3>=0 and s3<=100):
        total = (s1+s2+s3)/3

        if total>50:
            return 'GO'
        else:
            return 'NOGO'

'''

************************ 05 ***************************************

Given an integer and limit, return a list of even multiples of the integer up to and including the limit.

For example, if integer = 3 and limit = 30, the returned list should be [0,6,12,18,24,30]. Note, 0 is a multiple of any integer except 0 itself.

def q1(integer, limit):
    pass

'''
############################# SOLUTION ##############################

def q1(integer, limit):
    list_integers = []
    for i in range(0, limit + 1):
        if i%2==0 and i%integer==0:
            list_integers.append(i)
    return list_integers

'''

************************ 06 ***************************************

Given two filenames, return a list whose elements consist of line numbers for which the two files differ. The first line is considered line 0.

def q1(f0, f1):
    pass

'''

############################# SOLUTION ##############################

def q1(f0, f1):
    differences_list = []
    
    with open(f0,'r') as file_1, open(f1,'r') as file_2:
        lines_1 = file_1.readlines()
        lines_2 = file_2.readlines()
    
    len_1 = len(lines_1)
    len_2 = len(lines_2)

    if len_1>len_2:
        for i in range(len_1):
            if lines_1[i]!=lines_2[i]:
                differences_list.append(i)
    elif len_2<len_1:
        for i in range(len_2):
            if lines_1[i]!=lines_2[i]:
                differences_list.append(i)
    else:
        for i in range(len_1):
            if lines_1[i]!=lines_2[i]:
                differences_list.append(i)
    
    return differences_list

file_1 = 'copy.txt'
file_2 = 'copy1.txt'

q1(file_1,file_2)

'''

************************ 07 ***************************************

As you iterate through the given list, return the first duplicate value you come across.

For example, if given [5,7,9,1,3,7,9,5], the returned value should be 7.

def q1(lst):
    pass
'''

############################# SOLUTION ##############################

def q1(lst):
    new_set = set()

    for number in lst:
        if number in new_set:
            return number
        new_set.add(number)
   
    return new_set


set1= [5,7,9,1,3,7,9,5]
print(q1(set1))

'''

************************ 08 ***************************************

Given a sentence as a string with words being separated by a single space, return the length of the shortest word.

def q1(strng):
    pass

'''
############################# SOLUTION ##############################

def q1(strng):
    list_temp = []
    for word in strng.split(" "):
        list_temp.append(word)
        
    res = min(len(ele) for ele in list_temp) 
    return res
sentence = 'Name my Mahlon'
q1(sentence)

'''
************************ 09 ***************************************

Given an alphanumeric string, return the character whose ascii value is that of the integer represenation of all of the digits in the string concatenated in the order in which they appear.

For example, given 'hell9oworld7', the returned character should be 'a' which has the ascii value of 97.


def q1(strng):
    pass
'''

############################# SOLUTION ##############################

def q1(strng):
    # Step 1: Extract all the digits from the string.
    digits = []
    for char in strng:
        if char.isdigit():
            digits.append(char)

    # Step 2: Concatenate them to form a new number.
    number_str = ""
    for digit in digits:
        number_str += digit

    # Step 3: Convert this number to an integer.
    ascii_val = int(number_str)

    # Step 4: Use the `chr` function to get the character with the ASCII value of that integer.
    result_char = chr(ascii_val)

    return result_char


'''

************************ 10 ***************************************

Given a list of positive integers sorted in ascending order, return the first non-consecutive value. If all values are consecutive, return None.

For example, given [1,2,3,4,6,7], the returned value should be 6.

def q1(arr):
    pass
    
'''

############################# SOLUTION PART 1 ##############################
def q1(arr):
    temp_1 = len(arr)
    for i in range(temp_1):
        if i<temp_1-1:
            if arr[i]!=arr[i+1]-1:
                return arr[i+1]
                
    return None


############################# SOLUTION PART 2 ##############################

def q1(arr):
    # Iterate over the list except the last element
    for i in range(len(arr) - 1):
        # If the difference between the current value and the next value is greater than 1
        if arr[i + 1] - arr[i] > 1:
            return arr[i + 1]

    # If all values are consecutive, return None
    return None

# Test
print(q1([1,2,3,4,6,7]))  # Expected output: 6