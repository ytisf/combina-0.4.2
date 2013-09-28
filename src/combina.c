/**
	@license GNU GPLv3
	PROJECT "combina"
	Copyright © 2004,2005,2006 Danilo Cicerone
	Copyleft 2013 Ohad Gopher & Yuval (tisf) Nativ

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
	@file combina.c
	@author Ohad Gopher and Yuval (tisf) Nativ yuval@see-security.com
	@date 2013-07-18
	@version 0.4.2
*/

#include "combina.h"
#include "sha2.h"

#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1
 
unsigned int nt_buffer[16];
unsigned int output[4];
char hex_format[34];
char itoa16[17] = "0123456789ABCDEF";

int
main (int argc, char **argv)
{
	struct arg_lit *perms =
		arg_lit0 ("c", NULL, "Combination without repetition");

	struct arg_lit *permr = arg_lit0 ("m", NULL, "Combination with repetition");

	struct arg_lit *dsemp =
		arg_lit0 ("d", NULL, "Permutation without repetition");

	struct arg_lit *dripe =
		arg_lit0 ("r", NULL, "Permutation with repetition (default)");

	struct arg_int *group =
		arg_int0 ("k", NULL, NULL,
		"define the length of the passwords (default is 3)");

	struct arg_int *pgrsv =
		arg_int0 ("p", NULL, NULL,
		"progressive length of the passwords (from p to k)");

	struct arg_lit *lalpha =
		arg_lit0 ("a", NULL, "add charset [abcdefghijklmnopqrstuvwxyz]");

	struct arg_lit *ualpha =
		arg_lit0 ("A", NULL, "add charset [ABCDEFGHIJKLMNOPQRSTUVWXYZ]");

	struct arg_lit *nume = arg_lit0 ("n", NULL, "add charset [0123456789]");

	struct arg_lit *spec =
		arg_lit0 ("s", NULL, "add charset [! \"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]");

	struct arg_str *defines =
		arg_strn (NULL, "user", "STRING", 0, argc + 2, "add your charset");

	struct arg_str *addb =
		arg_strn (NULL, "add-before", "STRING", 0, argc + 2,
		"add your const string before charset");

	struct arg_str *adda =
		arg_strn (NULL, "add-after", "STRING", 0, argc + 2,
		"add your const string after charset");

	struct arg_lit *to_md5 = arg_lit0 (NULL, "md5", "return the MD5 hash");

	struct arg_lit *to_sha1 = arg_lit0 (NULL, "sha1", "return the SHA1 hash");


        struct arg_lit *to_sha256 = arg_lit0 (NULL, "sha256", "return the SHA2 256 hash");	
        struct arg_lit *to_sha384 = arg_lit0 (NULL, "sha384", "return the SHA2 384 hash");	
        struct arg_lit *to_sha512 = arg_lit0 (NULL, "sha512", "return the SHA2 512 hash");	







        struct arg_lit *to_ntlm = arg_lit0 (NULL, "ntlm", "return the NTLM hash");






	struct arg_lit *help = arg_lit0 (NULL, "help", "print this help and exit");

	struct arg_lit *version =
		arg_lit0 (NULL, "version", "print version information and exit");

	struct arg_end *end = arg_end (20);

	void *argtable[] =
	{
		perms, permr, dsemp, dripe, group, pgrsv, lalpha, ualpha, nume, spec,
		defines, addb, adda, to_md5,to_sha1,to_sha256,to_sha384,to_sha512,to_ntlm, help, version, end
	};

	int nerrors;
	int exitcode = 0;

	/* verify the argtable[] entries were allocated sucessfully */
	if (arg_nullcheck (argtable) != 0)
	{
		/* NULL entries were detected, some allocations must have failed */
		printf ("%s: insufficient memory\n", progname);
		exitcode = 1;
		goto exit;
	}

	/* set any command line default values prior to parsing */
	group->ival[0] = 3;
	pgrsv->ival[0] = 1;

	/* Parse the command line as defined by argtable[] */
	nerrors = arg_parse (argc, argv, argtable);

	/* special case: '--help' takes precedence over error reporting */
	if (help->count > 0)
	{
		printf ("%s: A password generator that implements ", progname);
		printf ("the combinatorial analysis.\n");
		printf ("Usage: %s ", progname);
		arg_print_syntax (stdout, argtable, "\n");
		arg_print_glossary (stdout, argtable, "  %-20s %s\n");
		printf ("combina has been improved by Ohad Gopher & Yuval Nativ\n");
		printf ("of the See-Security group is in under GNU!\n");
		printf ("Report bugs and suggestions to yuval@see-security.com .\n");
		exitcode = 0;
		goto exit;
	}

	/* special case: '--version' takes precedence error reporting */
	if (version->count > 0)
	{
		printf ("%s 0.4.2\n", progname);
		printf ("Copyright (C) 2006 Danilo Cicerone.\n");
		printf ("Copyleft 2013, Ohad Gopher & Yuval (tisf) Nativ.\n");
		printf ("This is free software; see the source for copying ");
		printf ("conditions.  There is NO\nwarranty; not even for ");
		printf ("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n");
		exitcode = 0;
		goto exit;
	}

	/* If the parser returned any errors then display them and exit */
	if (nerrors > 0)
	{
		/* Display the error details contained in the arg_end struct. */
		arg_print_errors (stdout, end, progname);
		printf ("Try '%s --help' for more information.\n", progname);
		exitcode = 1;
		goto exit;
	}

	/* special case: combina with no command line options induces brief help */
	if (argc == 1)
	{
		printf ("Try '%s --help' for more information.\n", progname);
		exitcode = 0;
		goto exit;
	}

	if ( to_md5->count +to_sha1->count +to_sha256->count+to_sha384->count+to_sha512->count+to_ntlm->count > 1)
	{
		printf ("%s: select one hash at a time!\n", progname);
		exitcode = 0;
		goto exit;
	}

	/* normal case: take the command line options at face value */
	exitcode = comb_parser (perms->count, permr->count, dsemp->count,
		dripe->count, group->ival[0], pgrsv->ival[0],
		pgrsv->count, lalpha->count, ualpha->count,
		nume->count, spec->count, defines->sval,
		defines->count, addb->sval, addb->count, adda->sval,
		adda->count, to_md5->count, to_sha1->count,to_sha256->count,to_sha384->count,to_sha512->count,to_ntlm->count);

	exit:
	/* deallocate each non-null entry in argtable[] */
	arg_freetable (argtable, sizeof (argtable) / sizeof (argtable[0]));

	return exitcode;
}

/*----------------------------------------------------------------------------*/

int
comb_parser (int c, int t, int d, int r, int k, int p, int pc, int a, int A,
	int n, int s, const char **defines, int ndefines,
	const char **add_b, int naddb, const char **add_a, int nadda,
	int m, int sh,int sh256,int sh384,int sh512,int ntlm)
{
	unsigned int ncm = 0;
	int bk = 0;
	int ak = 0;

	flagOut = 0;

	if (a > 0)
		ncm += strlen (ALPHA_L);
	if (A > 0)
		ncm += strlen (ALPHA_U);
	if (n > 0)
		ncm += strlen (NUMERIC);
	if (s > 0)
		ncm += strlen (SPECIAL);
	if (ndefines != 0)
		ncm += strlen (defines[0]);

	if (naddb != 0)
		bk += strlen (add_b[0]);
	if (nadda != 0)
		ak += strlen (add_a[0]);

	lenSet = ncm;

	if (lenSet == 0)
	{
		printf ("%s : any defined charset!\n", progname);
		return 0;
	}

	if (((k < 1)) || (k + ak + bk > 1024))
	{
		printf ("%s : k has to be >= 1 and <= 1024\n", progname);
		return 0;
	}

	if ((k > ncm) && ((c > 0) || (d > 0)))
	{
		printf ("%s : k has to be <= length of the charset in \n", progname);
		printf ("Combination or Permutation without repetition.\n");
		return 0;
	}

	if ((p > k) || (p <= 0))
	{
		printf ("%s : p has to be <= k and p > 0\n", progname);
		return 0;
	}

	ncm += 1;
	setCh = (char *) malloc (ncm);
	if (setCh == NULL)
	{
		printf ("Memory allocation failed. Goodbye!");
		return 1;
	}

	memset (setCh, '\0', ncm);

	if (a > 0)
		strcat (setCh, ALPHA_L);
	if (A > 0)
		strcat (setCh, ALPHA_U);
	if (n > 0)
		strcat (setCh, NUMERIC);
	if (s > 0)
		strcat (setCh, SPECIAL);
	if (ndefines != 0)
		strcat (setCh, defines[0]);

	if (bk > 0)
	{
		beforeCmb = (char *) malloc (bk + 1);
		if (beforeCmb == NULL)
		{
			printf ("Memory allocation failed. Goodbye!");
			return 1;
		}
		memset (beforeCmb, '\0', bk + 1);
		strcat (beforeCmb, add_b[0]);
	}

	if (ak > 0)
	{
		afterCmb = (char *) malloc (ak + 1);
		if (afterCmb == NULL)
		{
			 printf ("Memory allocation failed. Goodbye!");
			 return 1;
		}
		memset (afterCmb, '\0', ak + 1);
		strcat (afterCmb, add_a[0]);
	}

	flagOut += 1;

	if ((m > 0) || (sh > 0) || (sh256 > 0) || (sh384 > 0) || (sh512 > 0) || (ntlm > 0))
	{
		ncm = 0;
		ncm += strlen (NUMERIC);
		ncm += strlen (ALPHA_L);
		ncm += 1;
		hex_def = (char *) malloc (ncm);
		if (hex_def == NULL)
		{
			printf ("Memory allocation failed. Goodbye!");
			return 1;
		}
		memset (hex_def, '\0', ncm);
		strcat (hex_def, NUMERIC);
		strcat (hex_def, ALPHA_L);
	}

	if (m > 0)
		flagOut += 2;
	if (sh > 0)
		flagOut += 4;
        if (sh256 > 0)
		flagOut += 6;
        if (sh384 > 0)
		flagOut += 8;
        if (sh512 > 0)
		flagOut += 10;

        if (ntlm > 0)
		flagOut += 12;

	if (pc > 0)
		nchar = p;
	else
		nchar = k;

	for (; nchar <= k; nchar++)
	{
		ncm = nchar + 1;

		actualCmb = (char *) malloc (ncm);
		if (actualCmb == NULL)
		{
			printf ("Memory allocation failed. Goodbye!");
			return 1;
		}

		finalCmb = (char *) malloc (ncm);
		if (finalCmb == NULL)
		{
			printf ("Memory allocation failed. Goodbye!");
			return 1;
		}

		memset (actualCmb, '\0', ncm);
		memset (finalCmb, '\0', ncm);

		ncm = bk + ak + nchar + 1;
		outCmb = (char *) malloc (ncm);
		if (outCmb == NULL)
		{
			printf ("Memory allocation failed. Goodbye!");
			return 1;
		}

		memset (outCmb, '\0', ncm);

		if (c > 0)
		{
			comb_pm_final ();
			comb_pm ();
		}
		else if (t > 0)
		{
			comb_dr_final ();
			comb_cr ();
		}
		else if (d > 0)
		{
			comb_ds_ps_final ();
			comb_ds_ps ();
		}
		else
		{
			comb_dr_final ();
			comb_dr ();
		}
	}

	free (setCh);
	free (actualCmb);
	free (finalCmb);
	free (hex_def);

	return 0;
}

/*----------------------------------------------------------------------------*/

void
comb_dr ()
{
	int ix[nchar], j;

	memset (ix, 0, sizeof (ix));

	ix[nchar - 1] = -1;

	while (strcmp (actualCmb, finalCmb) != 0)
	{
		for (j = nchar - 1; j >= 0; j--)
		{
			ix[j] = ix[j] + 1;
			if (ix[j] >= lenSet)
				ix[j] = 0;
			else
			{
				print_comb (ix);
				break;
			}
		}
	}
}

/*----------------------------------------------------------------------------*/

void
comb_cr ()
{
	int ix[nchar], j;
	int y = 0;
	char w = 0;

	memset (ix, 0, sizeof (ix));

	ix[nchar - 1] = -1;

	while (strcmp (actualCmb, finalCmb) != 0)
	{
		for (j = nchar - 1; j >= 0; j--)
		{
			if (w)
			{
				for (; y <= nchar - 1; y++)
					ix[y] = ix[j] + 1;
				w = 0;
			}
			ix[j] = ix[j] + 1;
			if (ix[j] >= lenSet)
			{
				w = 1;
				y = j;
			}
			else
			{
				print_comb (ix);
				break;
			}
		}
	}
}

/*----------------------------------------------------------------------------*/

void
comb_ds_ps ()
{
	int ix[nchar], j, x, nv;
	char insOk;

	memset (ix, 0, sizeof (ix));

	for (j = nchar - 1; j >= 0; j--)
	{
		ix[j] = j;
	}

	print_comb (ix);

	while (strcmp (actualCmb, finalCmb) != 0)
	{
		j = nchar - 1;
		do
		{
			nv = ix[j] + 1;
			if (nv >= lenSet)
				{
					nv = ix[j] = -1;
					--j;
				}
			else
			{
				insOk = 1;
				for (x = 0; x < nchar; x++)
				{
					if (nv == ix[x])
					{
						insOk = 0;
						break;
					}
				}
				ix[j] = nv;
				if (insOk)
					++j;
			}
		}
		while (j <= nchar - 1);
		print_comb (ix);
	}
}

/*----------------------------------------------------------------------------*/

void
comb_pm ()
{
	int ix[nchar], j, k;

	memset (ix, 0, sizeof (ix));

	for (j = nchar - 1; j >= 0; j--)
	 ix[j] = j;

	print_comb (ix);

	while (strcmp (actualCmb, finalCmb) != 0)
	{
		j = nchar - 1;
		while (ix[j] > lenSet - nchar - 1 + j)
			j -= 1;

		ix[j] = ix[j] + 1;
		for (k = j + 1; k < nchar; k++)
			ix[k] = ix[k - 1] + 1;

		print_comb (ix);
	}
}

/*----------------------------------------------------------------------------*/

void
comb_dr_final ()
{
	int k;

	for (k = 0; k < nchar; k++)
		finalCmb[k] = setCh[lenSet - 1];
}

/*----------------------------------------------------------------------------*/

void
comb_ds_ps_final ()
{
	int k;

	for (k = 0; k < nchar; k++)
		finalCmb[k] = setCh[lenSet - 1 - k];
}

/*----------------------------------------------------------------------------*/

void
comb_pm_final ()
{
	int k;

	for (k = 0; k < nchar; k++)
		finalCmb[nchar - k - 1] = setCh[lenSet - 1 - k];
}

/*----------------------------------------------------------------------------*/

void
print_comb (int *ix)
{
	int k;

	for (k = 0; k < nchar; k++)
	 actualCmb[k] = setCh[ix[k]];

	*outCmb = '\0';

	if (beforeCmb)
		strcat (outCmb, beforeCmb);
	if (actualCmb)
		strcat (outCmb, actualCmb);
	if (afterCmb)
		strcat (outCmb, afterCmb);

	switch (flagOut)
	{
		case 1:
			printf ("%s\n", outCmb);
			break;
		case 3:
			to_md5_string (outCmb);
			printf (" : ");
			printf ("%s\n", outCmb);
			break;
		case 5:
			to_sha1_string (outCmb);
			printf (" : ");
			printf ("%s\n", outCmb);
			break;
               case 7:
			to_sha256_string (outCmb);
			printf (" : ");
			printf ("%s\n", outCmb);
			break;
               case 9:
			to_sha384_string (outCmb);
			printf (" : ");
			printf ("%s\n", outCmb);
			break;

                case 11:
			to_sha512_string (outCmb);
			printf (" : ");
			printf ("%s\n", outCmb);
			break;
 
                case 13:
			to_ntlm_string (outCmb);
			printf (" : ");
			printf ("%s\n", outCmb);
			break;
	}
/*
	print_debug(ix);
	printf("%s\n", finalCmb);
*/
}

/*----------------------------------------------------------------------------*/

void
print_debug (int *ix)
{
	int k;

	for (k = 0; k < nchar; k++)
		printf ("[%d]", ix[k]);

	printf ("\n");
}

/*----------------------------------------------------------------------------*/

void
to_md5_string (char *pwd)
{
	int i, j;
	unsigned char sumbuf[16];
	unsigned char md5out[33];

	MD5_CTX mycontext;
	MD5_Init (&mycontext);
	MD5_Update (&mycontext, pwd, strlen (pwd));
	MD5_Final (sumbuf, &mycontext);

	for (i = 0; i < 16; i++)
	{
		j = sumbuf[i];
		md5out[i * 2] = hex_def[(j >> 4) & 0x0f];
		md5out[i * 2 + 1] = hex_def[j & 0x0f];
	}

	md5out[32] = '\0';
	printf ("%s", md5out);
}

/*----------------------------------------------------------------------------*/

void
to_sha1_string (char *pwd)
{
	int i, j;
	unsigned char sumbuf[20];
	unsigned char sha1out[41];

	SHA_CTX mycontext;
	SHA_Init((const u_int8_t *)&mycontext);
	SHA_Update(&mycontext, pwd, strlen (pwd));
	SHA_Final(sumbuf, &mycontext);

	for (i = 0; i < 20; i++)
	{
		j = sumbuf[i];
		sha1out[i * 2] = hex_def[(j >> 4) & 0x0f];
		sha1out[i * 2 + 1] = hex_def[j & 0x0f];
	}

	sha1out[40] = '\0';
	printf ("%s", sha1out);
}



void
to_sha256_string (char *pwd)
{
	int i, j;
	unsigned char sumbuf[64];
	unsigned char sha1out[65];

	SHA256_CTX mycontext;
	SHA256_Init (&mycontext);
	SHA256_Update (&mycontext, (unsigned char*)pwd, strlen (pwd));
	SHA256_Final (sumbuf, &mycontext);

	for (i = 0; i < 32; i++)
	{
		j = sumbuf[i];
		sha1out[i * 2] = hex_def[(j >> 4) & 0x0f];
		sha1out[i * 2 + 1] = hex_def[j & 0x0f];
	}

	sha1out[64] = '\0';
	printf ("%s", sha1out);
}

void
to_sha384_string (char *pwd)
{
	int i, j;
	unsigned char sumbuf[128];
	unsigned char sha1out[97];

	SHA512_CTX mycontext;
	SHA384_Init (&mycontext);
	SHA384_Update (&mycontext, (unsigned char*)pwd, strlen (pwd));
	SHA384_Final (sumbuf, &mycontext);

	for (i = 0; i < 48; i++)
	{
		j = sumbuf[i];
		sha1out[i * 2] = hex_def[(j >> 4) & 0x0f];
		sha1out[i * 2 + 1] = hex_def[j & 0x0f];
	}

	sha1out[96] = '\0';
	printf ("%s", sha1out);

}

void
to_sha512_string (char *pwd)
{
	int i, j;
	unsigned char sumbuf[128];
	unsigned char sha1out[129];

	SHA512_CTX mycontext;
	SHA512_Init (&mycontext);
	SHA512_Update (&mycontext, (unsigned char*)pwd, strlen (pwd));
	SHA512_Final (sumbuf, &mycontext);

	for (i = 0; i < 64; i++)
	{
		j = sumbuf[i];
		sha1out[i * 2] = hex_def[(j >> 4) & 0x0f];
		sha1out[i * 2 + 1] = hex_def[j & 0x0f];
	}

	sha1out[128] = '\0';
	printf ("%s", sha1out);
}


void
to_ntlm_string (char *pwd)
{
 NTLM(pwd);	
}

void NTLM(char *key)
{
/*	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// Prepare the string for hash calculation
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/	int i = 0;
	int length = strlen(key);
	memset(nt_buffer, 0, 16*4);
	for(i=0; i<length/2; i++)	
		nt_buffer[i] = key[2 * i] | (key[2 * i + 1] << 16);
 
/*	//padding
*/	if(length % 2 == 1)
		nt_buffer[i] = key[length - 1] | 0x800000;
	else
		nt_buffer[i] = 0x80;
/*	//put the length
*/	
	nt_buffer[14] = length << 4;
	
/*	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// NTLM hash calculation
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/	unsigned int a = INIT_A;
	unsigned int b = INIT_B;
	unsigned int c = INIT_C;
	unsigned int d = INIT_D;
 
	/* Round 1 */
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[0]  ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[1]  ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[2]  ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[3]  ;b = (b << 19) | (b >> 13);
 
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[4]  ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[5]  ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[6]  ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[7]  ;b = (b << 19) | (b >> 13);
 
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[8]  ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[9]  ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[10] ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[11] ;b = (b << 19) | (b >> 13);
 
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[12] ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[13] ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[14] ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[15] ;b = (b << 19) | (b >> 13);
 
	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] +SQRT_2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] +SQRT_2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] +SQRT_2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12]+SQRT_2; b = (b<<13) | (b>>19);
 
	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] +SQRT_2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] +SQRT_2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] +SQRT_2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13]+SQRT_2; b = (b<<13) | (b>>19);
 
	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] +SQRT_2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] +SQRT_2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10]+SQRT_2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14]+SQRT_2; b = (b<<13) | (b>>19);
 
	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] +SQRT_2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] +SQRT_2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11]+SQRT_2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[15]+SQRT_2; b = (b<<13) | (b>>19);
 
	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[8]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[4]  +  SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[12] +  SQRT_3; b = (b << 15) | (b >> 17);
 
	a += (d ^ c ^ b) + nt_buffer[2]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[10] +  SQRT_3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[6]  +  SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[14] +  SQRT_3; b = (b << 15) | (b >> 17);
 
	a += (d ^ c ^ b) + nt_buffer[1]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[9]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[5]  +  SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[13] +  SQRT_3; b = (b << 15) | (b >> 17);
 
	a += (d ^ c ^ b) + nt_buffer[3]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[11] +  SQRT_3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[7]  +  SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[15] +  SQRT_3; b = (b << 15) | (b >> 17);
 
	output[0] = a + INIT_A;
	output[1] = b + INIT_B;
	output[2] = c + INIT_C;
	output[3] = d + INIT_D;
/*	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// Convert the hash to hex (for being readable)
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/	for(i=0; i<4; i++)
	{
		int j = 0;
		unsigned int n = output[i];
/*		//iterate the bytes of the integer		
*/		for(; j<4; j++)
		{
			unsigned int convert = n % 256;
			hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
			convert = convert / 16;
			hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
			n = n / 256;
		}	
	}
/*	//null terminate the string
*/	hex_format[33] ='\0';
        printf ("%s", hex_format);
      
}

/*----------------------------------------------------------------------------*/
