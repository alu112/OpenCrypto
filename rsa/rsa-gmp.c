/*
   Copyright 2020 Andrew Li, Gavin Li

   li.andrew.mail@gmail.com
   gavinux@gmail.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
 
int main(void)
{
    mpz_t n, d, e, pt, ct;
 
    mpz_init(pt);
    mpz_init(ct);
    mpz_init_set_str(n, "9516311845790656153499716760847001433441357", 10);
    mpz_init_set_str(e, "65537", 10);
    mpz_init_set_str(d, "5617843187844953170308463622230283376298685", 10);
 
    const char *plaintext = "Rossetta Code";
    mpz_import(pt, strlen(plaintext), 1, 1, 0, 0, plaintext);
 
    if (mpz_cmp(pt, n) > 0)
        abort();
 
    mpz_powm(ct, pt, e, n);
    gmp_printf("Encoded:   %Zd\n", ct);
 
    mpz_powm(pt, ct, d, n);
    gmp_printf("Decoded:   %Zd\n", pt);
 
    char buffer[64];
    mpz_export(buffer, NULL, 1, 1, 0, 0, pt);
    printf("As String: %s\n", buffer);
 
    mpz_clears(pt, ct, n, e, d, NULL);
    return 0;
}

