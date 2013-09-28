/**
	@license GNU GPLv2
	PROJECT "combina"
	Copyright © 2004,2005,2006 Danilo Cicerone

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software Foundation,
	Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
*/

/**
	@file combina.h
	@author Danilo Cicerone info@digitazero.org
	@date 2006-06-21
	@version 0.4.1
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argtable2.h>
#include <openssl/md5.h>
/*#include <openssl/sha.h>*/
#include "sha2.h"

/**
	@brief program name.
*/
const char *progname = "combina";

/**
	@brief low alpha charset.
*/
const char *ALPHA_L = "abcdefghijklmnopqrstuvwxyz";

/**
	@brief upper alpha charset.
*/
const char *ALPHA_U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/**
	@brief numeric charset.
*/
const char *NUMERIC = "0123456789";

/**
	@brief special charset.
*/
const char *SPECIAL = "! \"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/**
	@brief Argument parser by argtable2.
*/
int
comb_parser (int c, int t, int d, int r, int k, int p, int pc, int a, int A,
	int n, int s, const char **defines, int ndefines,
	const char **add_b, int naddb, const char **add_a, int nadda,
	int m, int sh,int sh256,int sh384,int sh512,int ntlm);
/**
	@brief It performs the Permutation with repetition.
*/
void
comb_dr();

/**
	@brief It performs the Combination with repetition.
*/
void
comb_cr();

/**
	@brief It performs the Permutation without repetition.
*/
void
comb_ds_ps();

/**
	@brief It performs the Combination without repetition.
*/
void
comb_pm();

/**
	@brief Calculate the last combination for the Permutation with repetition
	and the Combination with repetition.
*/
void
comb_dr_final();

/**
	@brief Calculate the last combination for the Permutation without
	repetition.
*/
void
comb_ds_ps_final();

/**
	@brief Calculate the last combination for the Combination without
	repetition.
*/
void
comb_pm_final();

/**
	@brief Calculate the MD5 hash for last actual combination.
*/
void
to_md5_string(char *pwd);

/**
	@brief Calculate the SHA1 hash for last actual combination.
*/
void
to_sha1_string(char *pwd);

void
to_sha256_string (char *pwd);
void
to_sha384_string (char *pwd);
void
to_sha512_string (char *pwd);


/**
	@brief Calculate the NTLM hash for last actual combination.
*/
void
to_ntlm_string(char *pwd);



void NTLM(char *key);



/**
	@brief Realize the combination.
*/
void
print_comb(int *ix);

/**
	@brief Debug print combination.
*/
void
print_debug(int *ix);

/**
	@brief It stores the number of chars for group.
*/
unsigned int nchar;

/**
	@brief It stores the lenght of total charset.
*/
unsigned int lenSet;

/**
	@brief It stores the printing options.
*/
unsigned char flagOut;

/**
	@brief It stores the charset.
*/
char *setCh;

/**
	@brief It stores the final combination.
*/
char *finalCmb;

/**
	@brief It stores the actual combination to compare.
*/
char *actualCmb;

/**
	@brief It stores the const string to add before the combination.
*/
char *beforeCmb;

/**
	@brief It stores the const string to add after the combination.
*/
char *afterCmb;

/**
	@brief It stores the printable combination.
*/
char *outCmb;

/**
	@brief It stores charset to conversion md5 hash in hex.
*/
char *hex_def;
