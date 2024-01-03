## Reverse Enginnering ## 

1. What is %RAX and %EAX main purpose?

a. They are the first return registers for x86-64 and x86

2. What is %RIP and %EIP main purpose?

a. %RIP/%EIP are the 64 bit and 32 bit instruction pointers that hold the memory address to the next instruction

3. What is %RBP and %EBP main purpose?

a. They are the 64 bit and 32 bit stack base pointers

4. What is %R8 size in bits?

64

5. Which of these registers has a size of 32 bits?

%R12D

6. What register does the JE instruction rely upon?

a. Flags

7. What flag does the JE instruction rely upon?

Zero Flag

8. What does the CMP instruction do?

a. Compares 2 values via subtraction

9. What value is on the top of the stack?

Main:
    Mov R8, 25
    Push R8
    Mov R10, 50
    Push R10
    Pop RAX`

The value on top of the stack is 25

10. What is the return register? 

50

11. What value is returned?

Main:
    Mov R9, 5 
    Mov R10, 20
    Add R10, R9
    CMP R10, R9
    JE Clean
    Mov RAX, 14
    ret

Clean:
    Mov RAX, 0
    ret

The value returned is 14

12. What does the printf() function do?

a. It sends formatted output to standard out (E.g. the terminal)

13. What does the fgets() function do?

It reads a line from the specified stream and stores it into a character array

14. What does the strcmp() function do?

It compares two strings (character arrays)

15. What is a successful return code for the strcmp() function if the two strings are the same?

a. 0

16. What is main()?

a. It is the designated entry point to a program

17. What is num1’s variable type?

int main(void){
    int num1 = 77;
    printf("%d",num1);
    return 0;
}

num1's variable type is an integer 

18. What is num1's value? 

77

19. What value is printed to the terminal upon execution?

77

20. What is “%d” in this program?

%d is a digit placeholder within printf()

What is important about “return 0”?

A return code of 0 is generally a clean exit of the program

21. What is returned to stdout when executed?

int main(void){
    char word1[4] = "word";
    char word2[5] = "words";
    if(strcmp(word1,word2)==0){
        printf("same");
    }else{
        printf("different");
    }
}

What is returned is different 

