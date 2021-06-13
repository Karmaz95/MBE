#include <stdio.h>

//cracker for LAB2
int main()
{
    char *char_ptr, pass[] = "kw6PZq3Zd;ekR[_1"; 
    int pass_length = 17;

    for(int i = 0; i < pass_length; ++i)
    {
        char_ptr = &pass[i];
    	printf("%c", (*char_ptr ^ (i+1)));
    }
    
    return 0;
}