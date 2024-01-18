## Reverse Enginnering 2 ##

press h key to convert 

search -> for strings -> type the string. 



proxychains scp -r student@192.168.28.111:192.168.28.111/longTermStorage student@10.50.27.161:C:\Users\student\Desktop\TEMP_FOLDER_192.168


## Reverse Enginnering 2 ##

#### Entry.exe 5 ####

1. Situation: Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided: compiled executable: (entry.exe) source code: (entry.c) Task: Run the executable with expected input and retrieve success message. Method: disassemble the executable and follow the program’s execution to discover its f unctionality, and expected input.

Ensure that before you move on from this challenge that you have fully understood what you have done to disassemble and reverse engineer this binary and how it is related to the provided source code.

T1
Hostname: web.site.donovia
IP: 192.168.28.111
OS: unknown
Creds: comrade::StudentWebExploitPassword
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Extract approved binaries under directory titled "longTermStorage".

What is the key for this binary?
step 1: ssh into the linops: `ssh student@10.50.24.96`

Step 1: Create a Dynamic tunnel to Jumpbox `ssh student@10.50.23.132 -D 9050`

Step 2: Scan the Donovian Ip to see what ports are open `proxychains nmap -sT -Pn 192.168.28.111`

![Alt Text](reverse_engineering_images/reverse_engineering_2_01.png)

Step 3: wget the http server since port 80 is open and also from the lonTermStorage directory `proxychains wget -r http://192.168.28.111/longTermStorage`

![Alt Text](reverse_engineering_images/reverse_engineering_2_02.png)

Step 4: longtermStorage has entry.c and entry.exe files on it

Step 5: Download Win SCP on the Windows box---open the win SCP application

Login with your lin ops IP: 10.50.40.1

User: student

Pass: password

Copy the file from linu box(right side) to the windows (left side)

![Alt Text](reverse_engineering_images/reverse_engineering_2_03.png)

Key: 123@magicKey

#### Basic Algorithm 5 ####

2. Basic Algorithm

a. Situation: Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

b. Provided: compiled executable: (basic1.exe) Task: Run the executable and retrieve a successful message using the binary's key. Method: disassemble the executable and follow the program’s execution to discover its functionality and expected input.

c. Add the value of all of the keys together. What is the MD5 hash of this sum?

Step 1: Copy the file to linops: `scp -r 192.168.28.111/longTermStorage student@10.50.27.161:C:/Users/student/Desktop/TEMP_FOLDER_192.168`

Step 1: Open Ghidra and import the file to Ghidra

Step 2: Open .exe on cmd and run the file with random input

![Alt Text](reverse_engineering_images/reverse_engineering_2_04.png)

Step 5:

![Alt Text](reverse_engineering_images/reverse_engineering_2_05.png)

Step 6: Search string for success and open the respective function. You will find: 

undefined4 __cdecl FUN_004010a0(byte *param_1)

{
  int iVar1;
  int local_8;
  
  iVar1 = FUN_00404a5c(param_1);
  local_8 = 2;
  while( true ) {
    if (11 < local_8) {
      return 12;
    }
    if (local_8 * 46 == iVar1) break;
    local_8 = local_8 + 1;
  }
  return 13519;
}

Here, the while loop says if 11 <local_8 = 2 this condition is meet the loop continues

Now looking at if statement and going through the iteration until the condition is meet which is 11<local_8

So we iterate to 11

92 + 138 + 184 + 230 + 276 + 322 + 368 + 414 + 460 + 506 = 2990

to get the answer do the: ` echo "2990" | md5sum `

Answer -> 79bc18f6cbd3b2290cbd69c190d62bc6

#### Software Doing Software Things 1 8 ####

3. Provided: compiled executable: (sdst3.exe) Task: Run the executable with expected input and retrieve success message. Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

Enter the complete name of one of the items used to determine the success of the binary's execution.

ENV11

#### Software Doing Software Things 1 8 ####

4. Situation: Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided: compiled executable: (sdst.exe) Task: Run the executable with expected input and retrieve success message. 
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

What is the MD5 hash of the key (specifically the value and not location) that the program required?

Step 1. Open Ghidra

Step 2. Import sdst.exe

Step 3. Seach string success 

Step 4. Open the function with the success message. 

```undefined4 FUN_00401100(void)

{
  FILE *pFVar1;
  int iVar2;
  char local_8 [4];
  
  FUN_00401000();
  FUN_00401280((wchar_t *)s_Press_enter_key:_004220c0);
  pFVar1 = (FILE *)FUN_004047cc(0);
  FUN_00404a84(local_8,2,pFVar1);
  iVar2 = FUN_00401060();
  if (iVar2 == 0x2a2) {
    FUN_00401280((wchar_t *)s_Success!_004220d4);
    Sleep(5000);
  }
  else {
    FUN_00401280((wchar_t *)s_Invalid_key._004220e0);
    Sleep(5000);
  }
  return 0;
}
```
Opening the FUN_00401000() function we find: 

void FUN_00401000(void)

``` 
{
  FILE *pFVar1;
  
  pFVar1 = _fopen(s_C:\Users\Public\Documents\secret_00422004,&DAT_00422000);
  _fclose(pFVar1);
  pFVar1 = _fopen(s_C:\Users\Public\Documents\secret_00422030,&DAT_0042202c);
  FID_conflict:_fwprintf(pFVar1,(wchar_t *)&DAT_00422058);
  _fclose(pFVar1);
  return;

} 
```

Opening secret_00422004 -> I find the value 80111

Look at the function that generates  iVar2 = FUN_00401060(); we get, 

```
undefined4 FUN_00401060(void)

{
  undefined4 uVar1;
  int local_10;
  int local_c;
  FILE *local_8;
  
  local_8 = _fopen(s_C:\Users\Public\Documents\secret_00422064,&DAT_00422060);
  FID_conflict:_fwprintf(local_8,(wchar_t *)&DAT_0042208c,&local_c);
  _fclose(local_8);
  local_8 = _fopen(s_C:\Users\Public\Documents\secret_00422094,&DAT_00422090);
  FID_conflict:_fwprintf(local_8,(wchar_t *)&DAT_004220bc,&local_10);
  _fclose(local_8);
  if (local_c + local_10 == 17535) {
    uVar1 = 0x2a2;
  }
  else {
    uVar1 = 0x44f6;
  }
  return uVar1;
}
```

For the message to be successful we have to have 17535 and the other value is 8011 so subtracting these two the value that we need is -> 9524

![Alt Text](reverse_engineering_images/reverse_engineering_2_06.png)


#### Software Doing Software Things 2 8 ####

5. Situation: Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided: compiled executable: (sdst2.exe) Task: Run the executable with expected input and retrieve success message. Method: disassemble the executable and follow the program’s execution to discover its f unctionality, and expected input.

Show the instructor how you solved this to be awarded points.

![Alt Text](reverse_engineering_images/reverse_engineering_2_07.png)

Ra the program and found the success----followed the function

Here on the RegOpenKeyExA---- function is saying that the value will be on the MS registry

![Alt Text](reverse_engineering_images/reverse_engineering_2_08.png)

Here, registry was 0 initially

RegQueryValueExA function = This function retrieves the type and data for a specified value name associated with an open registry key

So, we know local_208 value is 0 because the registry default was 0

Now, to see the local_210 value which is located at publci documents and sec

![Alt Text](reverse_engineering_images/reverse_engineering_2_09.png)

Clicking the file path gives the file name which is secret3.txt

Opening the file is empty as well.

Now, we know for the function to be run the sVar1 should not be be 0

The strcmp() compares two strings character by character. If the strings are equal, the function returns 0.

Local_108 value is at the secrret3.txt which we know is empty as well.

Now, for this function to run value of sVar1 cannot be 0. because the sVar1=_strlen(local_108) is looking for the string length. Reason the function does not run if value is 0 is because it skips the function. So for function to run value os sVar1 which is string length should not be 0.

We can input any numberas var1 but it has to match the registry number as sVar1 is comparing it with registry number

![Alt Text](reverse_engineering_images/reverse_engineering_2_10.png)

##### Procedural Steps #####

Step 1. Open Ghidra

Step 2. Import sdst2.exe

Step 3. Seach string success 

Step 4. Open the function with the success message. 


```undefined4 FUN_00401170(void)

{
  BOOL BVar1;
  FILE *pFVar2;
  int iVar3;
  int local_10;
  HANDLE local_c;
  char local_8 [4];
  
  BVar1 = IsDebuggerPresent();
  if (BVar1 == 0) {
    local_c = (HANDLE)0xffffffff;
    local_10 = 0;
    local_c = GetCurrentProcess();
    CheckRemoteDebuggerPresent(local_c,&local_10);
    if (local_10 == 0) {
      FUN_00401000();
      FUN_00401320((wchar_t *)s_Press_enter_key:_004200a4);
      pFVar2 = (FILE *)___acrt_iob_func(0);
      FUN_0040325f(local_8,2,pFVar2);
      iVar3 = FUN_00401060();
      if (iVar3 == 0x92) {
        FUN_00401320((wchar_t *)s_Success!_004200b8);
        Sleep(5000);
      }
      else {
        FUN_00401320((wchar_t *)s_Invalid_key._004200c4);
        Sleep(5000);
      }
    }
    else {
      FUN_00401320((wchar_t *)s_Stop_Cheating._00420094);
      Sleep(5000);
    }
  }
  else {
    FUN_00401320((wchar_t *)s_Stop_cheating._004200d4);
    Sleep(5000);
  }
  return 0;
}

```

Step 5. Open this function -> iVar3 = FUN_00401060();

We get: 

```void FUN_00401060(void)

{
  size_t sVar1;
  DWORD local_218;
  DWORD local_214;
  FILE *local_210;
  HKEY local_20c;
  BYTE local_208 [256];
  char local_108 [256];
  uint local_8;
  
  local_8 = DAT_004200e8 ^ (uint)&stack0xfffffffc;
  local_214 = 0x100;
  local_218 = 1;
  RegOpenKeyExA((HKEY)0x80000001,s_SOFTWARE\MICROSOFT\KEYED3_00420048,0,0xf003f,&local_20c);
  RegQueryValueExA(local_20c,(LPCSTR)0x0,(LPDWORD)0x0,&local_218,local_208,&local_214);
  RegCloseKey(local_20c);
  local_210 = _fopen(s_C:\Users\Public\Documents\secret_00420068,&DAT_00420064);
  FID_conflict:_fwprintf(local_210,(wchar_t *)&DAT_00420090,local_108);
  _fclose(local_210);
  sVar1 = _strlen(local_108);
  if (sVar1 != 0) {
    _strcmp((char *)local_208,local_108);
  }
  FUN_0040135a(local_8 ^ (uint)&stack0xfffffffc);
  return;
}
```
Run sdst2.exe

Step 5. Open Registry Editor
    Registry Editor -> HKEY_CURRENT_USER -> SOFTWARE -> Microsoft -> KEYED3

    The value here is 0, change the value to 1 or whatever you want.

Step 6. Open C:\Users\Public\Documents\secret3.txt

    Change the value to 1

Re-run sdst2.exe and you shoud be in .

#### Software Doing Software Things 3 8 ####

6. Situation:

Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures. Provided: compiled executable: (sdst3.exe) Task: Run the executable with expected input and retrieve success message. Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

What value determines successful execution of the binary?

![Alt Text](reverse_engineering_images/reverse_engineering_2_11.png)

For this function to run uVar1 == 9985, here uVar1 = checkKey() which is our function. Following thr checkkey() function

![Alt Text](reverse_engineering_images/reverse_engineering_2_12.png)

The C library function int atoi(const char *str) converts the string argument str to an integer (type int).

![Alt Text](reverse_engineering_images/reverse_engineering_2_13.png)

Here variable 1 and 2 determines if uVar4= 9985

##### Procedural Steps #####

Step 1. Open Ghidra

Step 2. Import sdst3.exe

Step 3. Seach string success 

Step 4. Open the function with the success message. 


undefined8 main(void)

```
{
  undefined8 uVar1;
  long in_FS_OFFSET;
  char local_18 [8];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  createKey();
  printf("Press enter key: ");
  fgets(local_18,2,stdin);
  uVar1 = checkKey();
  if ((int)uVar1 == 9985) {
    puts("Success!");
    usleep(5000);
  }
  else {
    puts("Invalid key.");
    usleep(5000);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Step 5. Checking checkKey(); function we get;

```undefined8 checkKey(void)

{
  int iVar1;
  int iVar2;
  FILE *__stream;
  char *pcVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  char local_448 [16];
  undefined local_438 [512];
  char local_238 [552];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("/tmp/key","r+");
  while( true ) {
    pcVar3 = fgets(local_238,0x226,__stream);
    if (pcVar3 == (char *)0x0) break;
    __isoc99_sscanf(local_238,"%s %s",local_438,local_448);
  }
  iVar1 = atoi(local_448);
  if (iVar1 < 1) {
    uVar4 = 1768;
  }
  else {
    pcVar3 = getenv("ENV11");
    iVar2 = atoi(pcVar3);
    if (iVar2 < 1) {
      uVar4 = 1768;
    }
    else if (iVar1 + iVar2 == 18765) {
      uVar4 = 9985;
    }
    else {
      uVar4 = 1768;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar4;
}
```
The answer will be 18765

#### Software Doing Software Things 3 - Part 2 5 ####

Level II Challenge

Provided:
compiled executable: (sdst3.exe)
Task: Run the executable with expected input and retrieve success message.
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

Enter the complete name of one of the items used to determine the success of the binary's execution.

Ans -> pcVar3 = getenv("ENV11");
Answ -> ENV11

#### PE Patching 8 ####

7. Situation: Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided: compiled executable: (patching.exe) Task: Provide a patched executable that displays a "Successful" message for every key entered Method: Utilize RE toolset provided to patch additional or modified functionality to the binary.

Use your imagination to show the patched file to the instructor and they will give you the points if you have completed the challenge successfully

![Alt Text](reverse_engineering_images/reverse_engineering_2_14.png)

##### Procedural Steps #####

Step 1. Open Ghidra

Step 2. Import patching.exe

Step 3. Seach string success 

Step 4. Open the function with the success message. 

void FUN_00401000(void)

{
  FILE *pFVar1;
  int iVar2;
  byte local_1c [20];
  uint local_8;
  
  local_8 = DAT_0041c02c ^ (uint)&stack0xfffffffc;
  FUN_00401160((wchar_t *)s_Enter_Key:_0041c000);
  pFVar1 = (FILE *)FUN_00404b59(0);
  FUN_00404d22((char *)local_1c,0x14,pFVar1);
  _strtok((char *)local_1c,&DAT_0041c00c);
  iVar2 = FUN_004010a0(local_1c);
  if (iVar2 == 0x34cf) {
    FUN_00401160((wchar_t *)s_Success!_0041c010);
    Sleep(5000);
  }
  else {
    FUN_00401160((wchar_t *)s_Invalid_key._0041c01c);
    Sleep(5000);
  }
  @__security_check_cookie@4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

open ivar2 function -> iVar2 = FUN_004010a0(local_1c);

undefined4 __cdecl FUN_004010a0(byte *param_1)

{
  int iVar1;
  int local_8;
  
  iVar1 = FUN_00404a6c(param_1);
  local_8 = 2;
  while( true ) {
    if (0xe < local_8) {
      return 0xc;
    }
    if (local_8 * local_8 + local_8 + 0x1d == iVar1) break;
    local_8 = local_8 + 1;
  }
  return 0x34cf;
}

We need to skip this function so we need to redirect ivar2 to success... so we modify the JNZ call on top of it to redirect to success so change 0x00401078 to 0040105a. 

So, right click on 0x00401078 and select patch instructions. 
Change 0x00401078 to 0040105a

File -> Export Program, select binary format, select new name for the exported file and click okay. 

Go to the folder where it's saved -> C:\Users\student\TEMP_FOLDER_192.168

Rename Bin to exe file. 


