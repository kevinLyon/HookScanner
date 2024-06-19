# HookScanner
Simple HookScanner for EDR

Add you DLL and the function wath you want discovery if it is hooked by EDR or not.

how add your DLL?
````
PCHAR dll_lst[] = {
      "all functions you want the test",
      ....
};

````

add 'dll_lst' in 'pcLoot'
````
PCHAR* pcLoot[] = { ntdll_lst, kernel32_lst, dll_lst, ... };
````

add in 'sSizeLists'
````
..., sizeof(dll_lst) / sizeof(dll_lst[0]), ...
````

add the DLL name in 'pcOrderList' 
````
PWCHAR pcOrderList[] = { L"ntdll.dll", L"kernel32.dll", "dll_lst", .... };
````

## Run:
![banner](https://github.com/kevinLyon/HookScanner/blob/main/image/banner.jpg?raw=true)
> Why you need map all functions? ... it does not make sense .... 
