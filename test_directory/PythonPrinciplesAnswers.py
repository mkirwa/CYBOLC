# *************** CAPITAL INDEXES SOLUTION ***************

def capital_indexes(param):
    listCapital = []
    for i in range(0,len(param)):
        if param[i].isupper():
            listCapital.append(i)
    return listCapital
        
capital_indexes('reNTal')

# *************** MIDDLE LETTER SOLUTION ***************

import math

def mid(string_mid):
    list_mid_string = list(string_mid)
    if len(list_mid_string)%2==0:
        return ""
    else:
        index_string = math.ceil(len(list_mid_string)/2)
        return list_mid_string[index_string-1]

print(mid("abc"))
print(mid("aaaa"))


# *************** ONLINE STATUS SOLUTION ***************

def online_count(statuses):
    count = 0
    for key, value in statuses.items():
        if value=='online':
            count+=1
    return count

statuses = {
    "Alice": "online",
    "Bob": "offline",
    "Eve": "online",
}
online_count(statuses)


# *************** RANDOMNESS SOLUTION ***************

import random
def random_number():
    return random.randint(0,101)
print(random_number())

# *************** TYPE CHECK SOLUTION ***************

def only_ints(param1, param2):
    param1_type = type(param1)
    param2_type = type(param2)
    if 'int' in str(param1_type) and 'int' in str(param2_type):
        return True
    else:
        return False
    
only_ints(1,2)

# *************** DOUBLE LETTERS SOLUTION ***************

def double_letters(param_1):
    param_1_new = list(str(param_1))
    temp_1 = len(param_1_new)
    double_letters_present = False
    for i in range(temp_1):
        if i<temp_1-1:
            if param_1_new[i]==param_1_new[i+1]:
                double_letters_present = True
    return double_letters_present
                
print(double_letters('helo'))  

# *************** ADDING AND REMOVING DOTS SOLUTION ***************

def add_dots(string_dots):
    new_string = '.'.join(string_dots)
    return new_string
    
def remove_dots(string_dots):
    new_string = string_dots.replace('.','')
    return new_string
    

# *************** COUNTING SYLLABLES SOLUTION ***************

def count(string_new):
    count_dash = 0
    num = string_new.count('-')
    if num==0:
        count_dash = 1
    else:
        count_dash = num + 1
    return count_dash


# *************** ANAGRAMS SOLUTION ***************

def is_anagram(param1, param2):
    list_1 = list(param1)
    list_1.sort()
    list_2 = list(param2)
    list_2.sort()
    return list_1==list_2
        

# *************** FLATTEN A LIST SOLUTION ***************

def flatten(list_1):
    new_list = []
    for i in range(0,len(list_1)):
        new_list = new_list + list_1[i]
    return new_list

# *************** MIN-MAXING SOLUTION ***************

def largest_difference(list_1):
    new_list = list_1
    new_list.sort()
    return new_list[-1] - new_list[0]


# *************** DIVISIBLE BY 3 SOLUTION ***************

def div_3(val):
    if int(val)%3 == 0:
        return True
    else:
        return False

# *************** TIC TAC TOE INPUT SOLUTION ***************

def get_row_col(value_temp):
    board = [["A1", "B1", "C1"],["A2", "B2", "C2"],["A3", "B3", "C3"]]
    list_temp = []
    for i in range(len(board)):
        for j in range(len(board[i])):
            if value_temp in board[i][j]:
                list_temp.append(i)
                list_temp.append(j)
                return tuple(list_temp)
          
value_temp = "A3"
print(get_row_col(value_temp))

# *************** PALINDROME SOLUTION ***************

def palindrome(string):
    if string==string[::-1]:
        return True
    else:
        return False


# *************** UP AND DOWN SOLUTION ***************

def up_down(num):
    num1 = int(num) - 1
    num2 = int(num) + 1
    tuple_new = (num1, num2)
    return tuple_new

# *************** CONSECUTIVE ZEROS SOLUTION ***************

def consecutive_zeros(zeros_str):
    count = 0
    max_count = 0 
    new_list = list(str(zeros_str))
    
    for i in range(0, len(new_list)):
        if new_list[i]=='0':
            count = count + 1
            if count>max_count:
                max_count = count
        else:
            count = 0
    return max_count       
    
consecutive_zeros(1001101000110)

# *************** ALL EQUAL SOLUTION ***************


def all_equal(input_list):
    if not input_list:
        return True
    
    first_element = input_list[0]
    return_value = True
    for i in range(0, len(input_list)):
        if first_element != input_list[i]:
            return_value = False
    return return_value
   
input_list = [1,2,1,1]
print(all_equal(input_list))
    

# *************** BOOLEAN AND SOLUTION ***************

def triple_and(param1, param2, param3):
    if param1==True and param2==True and param3==True:
        return True
    else:
        return False

# *************** WRITING SHORT CODE SOLUTION ***************

def convert(list_numbers):
    return list(map(str,list_numbers))


# *************** CUSTOM ZIP SOLUTION ***************

def zap(list1, list2):
    new_tuple = list(map(lambda x,y:(x,y), list1,list2))
    return new_tuple

list1_ = [0, 1, 2, 3]
list2_ = [5, 6, 7, 8]
zap(list1_,list2_)

# *************** SOLUTION VALIDATION SOLUTION ***************


def validate(code):
    if "def" not in code:
        return "missing def"
    if ":" not in code:
        return "missing :"
    if "(" not in code or ")" not in code:
        return "missing paren"
    if "("+")" in code:
        return "missing param"
    if "    " not in code:
        return "missing indent"
    if "validate" not in code:
        return "wrong name"
    if "return" not in code:
        return "missing return"
    
    return True
    
code_to_validate = 'def validate(one):\n    return print(123)\n'

print(validate(code_to_validate))  # Output should be True


# *************** LIST XOR SOLUTION ***************

def list_xor(n,list1,list2):
    for i, list1_elem in enumerate(list1):
        if n==list1[i] and n==list2[i] or n!=list1[i] and n!=list2[i]:
            n = False
        else:
            n = True
        return n

print(list_xor(1, [0, 0, 0], [4, 5, 6]))

# *************** COUNTING PARAMETERS SOLUTION ***************

def param_count(*args):
    return len(args)
print(param_count(1,2,3))

# *************** THOUSANDS SEPARATOR SOLUTION ***************

def format_number(param):
    return '{:,}'.format(param)
print(format_number(1000000))


