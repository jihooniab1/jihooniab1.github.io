int main(void)
{
    char* pcVideoMemory = ( char* ) 0xB8000; 
    int i = 0; 

    while(1)
    {
        pcVideoMemory[ i ] = 0;
        pcVideoMemory[ i + 1 ] = 0x0A;

        i += 2;

        if ( i >= 80 * 25 * 2 )
        {
            break;
        }
    }
}