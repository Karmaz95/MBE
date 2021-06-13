#include <stdio.h>

//cracker for LAB1
int main()
{
    char *char_ptr, pass[] = "5tr0vZBrX:xTyR-P!"; 
    int pass_length = 17;

    for(int i = 0; i < pass_length; ++i)
    {
        char_ptr = &pass[i];
    	printf("%c", (*char_ptr ^ i));
    }
    
    return 0;
}
