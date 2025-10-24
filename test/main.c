#include <stdio.h>

int foo(){
    printf("THIS IS FUNCTION ONEZA");
    return 10;
}

int main(){
    int secret = foo();
    printf("%d", secret);
    return 0;
}